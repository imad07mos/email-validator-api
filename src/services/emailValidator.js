// src/services/emailValidator.js
const validator = require('validator');
const dns = require('dns');
const net = require('net'); // For TCP sockets
const tls = require('tls'); // For STARTTLS/SMTPS
const mailcheck = require('mailcheck');
const pLimit = require('p-limit').default; // Correct import for p-limit's default export
const config = require('../config');

// Load custom lists
const disposableDomains = require('../utils/disposableDomains');
const blacklistedDomains = require('../utils/blacklistedDomains');
const knownProviders = require('../utils/knownProviders');
const parkingDomainNS = require('../utils/parkingDomainNS');
const { mispWarningDomains, mispWarningEmails } = require('../utils/mispWarningLists'); // NEW: Import MISP lists

// Optional: Word removal list
const wordRemovalList = new Set([
    // Common spam and abuse indicators
    "spam", "spamword", "abuse", "junk", "scam", "bot", "phishing", "fraud",
    "malware", "virus", "trojan", "suspicious", "blacklist", "spammer",
    
    // Admin or system accounts
    "administrator", "root", "noreply", "no-reply", "donotreply", 
    "support", "helpdesk", "system", "postmaster", "webmaster", "sysadmin",
    "daemon", "mailer", "autoresponder", "automated",
    
    // Fake/test accounts
    "test", "testing", "testaccount", "testuser", "demo", "example", 
    "sample", "placeholder", "dummy", "mockuser", "trial", "beta",
    
    // Offensive or restricted content
    "banned", "illegal", "hacker", "exploit", "attack", "malicious",
    "unauthorized", "forbidden", "restricted", "violation", "breach",
    
    // Marketing and promotional
    "newsletter", "marketing", "sales", "unsubscribe", "offers", "promo",
    "promotion", "advertising", "campaign", "bulk", "broadcast", "mass",
    "commercial", "solicitation", "affiliate", "referral",
    
    // Temporary and throwaway accounts  
    "temp", "temporary", "disposable", "throwaway", "burner", "oneuse",
    "shortterm", "instant", "quick", "fast", "immediate",
    
    // Generic and placeholder terms
    "null", "undefined", "anonymous", "guest", "user", "fake", "default",
    "generic", "random", "unknown", "nobody", "none", "empty", "blank",
    
    // Bot and automation indicators
    "robot", "crawler", "spider", "scraper", "automaton", "script",
    "program", "service", "process", "worker", "agent",
    
    // Suspicious patterns
    "generator", "creator", "maker", "builder", "factory", "producer",
    "harvester", "collector", "grabber", "extractor",
    
    // Common gibberish patterns (you may want to add regex patterns for these)
    "asdf", "qwerty", "123456", "abcdef", "xxxxxx", "zzzzzz",
    "aaaaaa", "111111", "000000", "testtest", "blahblah",
    
    // Professional red flags
    "intern", "trainee", "student", "learner", "beginner", "novice",
    "junior", "entry", "assistant", "helper", "volunteer",
    
    // Verification and validation issues
    "unverified", "invalid", "expired", "suspended", "disabled", "inactive",
    "pending", "waiting", "queued", "processing", "reviewing"
]);
// Initialize the p-limit instance
const limit = pLimit(config.concurrencyLimit);


/**
 * Performs a single SMTP command and waits for a response.
 * @param {Socket} socket - The network socket (can be net.Socket or tls.TLSSocket).
 * @param {string} command - The SMTP command to send (e.g., "EHLO example.com\r\n").
 * @param {number[]} expectedCodes - An array of expected SMTP response codes (e.g., [250]).
 * @returns {Promise<object>} - { code: number, message: string } or throws an error.
 */
function sendSmtpCommand(socket, command, expectedCodes) {
    return new Promise((resolve, reject) => {
        let buffer = '';
        const timeoutId = setTimeout(() => {
            socket.destroy(new Error('SMTP read timeout'));
            reject(new Error(`SMTP read timeout for command: ${command.trim()}`));
        }, config.smtpReadTimeoutMs);

        const onData = (data) => {
            buffer += data.toString();
            const lines = buffer.split('\r\n');
            buffer = lines.pop(); // Keep incomplete last line in buffer

            for (const line of lines) {
                if (line.length === 0) continue;

                const code = parseInt(line.substring(0, 3), 10);
                const message = line.substring(4); // "250-MESSAGE" or "250 MESSAGE"

                if (!isNaN(code) && (line[3] === ' ' || line[3] === '-')) {
                    // Check if this is the final line of a multi-line response
                    if (line[3] === ' ' && expectedCodes.includes(code)) {
                        clearTimeout(timeoutId);
                        socket.removeListener('data', onData);
                        resolve({ code, message });
                        return;
                    } else if (line[3] === ' ' && !expectedCodes.includes(code)) {
                        clearTimeout(timeoutId);
                        socket.removeListener('data', onData);
                        // Specific error codes (550, 551, 552, 553, 554, 556) indicate user/mailbox issues
                        if ([550, 551, 552, 553, 554, 556].includes(code)) {
                            reject(new Error(`SMTP mailbox error ${code}: ${message}`));
                        } else if ([450, 451, 452].includes(code)) { // Transient errors
                             reject(new Error(`SMTP transient error ${code}: ${message}`));
                        } else if ([530, 535].includes(code)) { // Authentication errors
                             reject(new Error(`SMTP authentication error ${code}: ${message}`));
                        } else { // Other permanent errors
                             reject(new Error(`SMTP permanent error ${code}: ${message}`));
                        }
                        return;
                    }
                    // If line[3] is '-', it's a multi-line response continuation, just keep buffering
                }
            }
        };

        socket.on('data', onData);
        socket.write(command, (err) => {
            if (err) {
                clearTimeout(timeoutId);
                socket.removeListener('data', onData);
                reject(new Error(`Failed to write SMTP command: ${err.message}`));
            }
        });
    });
}


/**
 * Attempts to verify a mailbox using a specific, configured SMTP server.
 * This server will then handle the actual lookup against the target domain's MX records.
 * @param {string} email - The email to verify.
 * @param {string} fromEmail - The email address to use in MAIL FROM command.
 * @returns {Promise<boolean>} - True if mailbox seems to exist, false otherwise.
 */
async function checkMailboxExists(email, fromEmail) {
    let socket;
    try {
        const host = config.smtpHost;
        const port = config.smtpPort;

        if (!host) {
            throw new Error('SMTP_HOST is not configured for verification.');
        }

        // Determine if connecting via STARTTLS (port 587) or direct TLS (port 465)
        let isDirectTls = (port === config.smtpSecurePort);

        // 1. Connect to the configured SMTP server (TCP or TLS directly)
        if (isDirectTls) {
             // Direct TLS connection (SMTPS, usually port 465)
            socket = tls.connect({
                host: host,
                port: port,
                timeout: config.smtpConnectTimeoutMs,
                rejectUnauthorized: false // CAUTION: Set to true in production if you trust your certificates
            });
        } else {
             // Standard TCP connection (usually port 25 or 587, for STARTTLS later)
            socket = net.createConnection({ host: host, port: port, timeout: config.smtpConnectTimeoutMs });
        }


        const connectPromise = new Promise((resolve, reject) => {
            if (isDirectTls) {
                socket.once('secureConnect', () => resolve());
                socket.once('error', (err) => reject(new Error(`TLS connection failed to ${host}:${port}: ${err.message}`)));
            } else {
                socket.once('connect', () => resolve());
                socket.once('error', (err) => reject(new Error(`TCP connection failed to ${host}:${port}: ${err.message}`)));
            }
            socket.once('timeout', () => {
                socket.destroy(new Error('Connection timeout'));
                reject(new Error(`Connection timeout to ${host}:${port}`));
            });
        });

        await connectPromise;

        // 2. Wait for initial 220 greeting
        await sendSmtpCommand(socket, '', [220]); // Empty command, just wait for greeting

        // 3. Send EHLO
        const ehloResponse = await sendSmtpCommand(socket, `EHLO ${config.smtpVerificationFromEmail.split('@')[1]}\r\n`, [250]);

        // Check for STARTTLS support and upgrade if available (only if not already direct TLS)
        if (!isDirectTls && !socket.encrypted && ehloResponse.message.includes('STARTTLS')) {
            await sendSmtpCommand(socket, 'STARTTLS\r\n', [220]);
            socket = tls.connect({ socket: socket, servername: host, rejectUnauthorized: false }, () => { /* TLS handshake complete */ }); // CAUTION!

            const tlsHandshakePromise = new Promise((resolve, reject) => {
                socket.once('secureConnect', () => resolve());
                socket.once('error', (err) => reject(new Error(`TLS handshake failed: ${err.message}`)));
            });
            await tlsHandshakePromise;

            // Re-send EHLO after STARTTLS
            await sendSmtpCommand(socket, `EHLO ${config.smtpVerificationFromEmail.split('@')[1]}\r\n`, [250]);
        }

        // --- SMTP Authentication ---
        if (config.smtpUsername && config.smtpPassword) {
            // AUTH LOGIN mechanism (most common)
            await sendSmtpCommand(socket, 'AUTH LOGIN\r\n', [334]);
            await sendSmtpCommand(socket, Buffer.from(config.smtpUsername).toString('base64') + '\r\n', [334]);
            await sendSmtpCommand(socket, Buffer.from(config.smtpPassword).toString('base64') + '\r\n', [235]); // 235: Authentication successful
        }

        // 4. Send MAIL FROM
        await sendSmtpCommand(socket, `MAIL FROM:<${fromEmail}>\r\n`, [250]);

        // 5. Send RCPT TO (This is the core check performed via the configured SMTP server)
        await sendSmtpCommand(socket, `RCPT TO:<${email}>\r\n`, [250]);

        // If all commands succeeded, the mailbox appears to exist (from the perspective of our SMTP server)
        return true;

    } catch (error) {
        // Handle specific errors for clearer reasons
        if (error.message.includes('SMTP mailbox error')) {
            throw new Error(`Mailbox does not exist: ${error.message.split(': ')[1] || error.message}`);
        } else if (error.message.includes('SMTP transient error')) {
             throw new Error(`Mailbox verification failed (transient error): ${error.message.split(': ')[1] || error.message}`);
        } else if (error.message.includes('SMTP permanent error')) {
             throw new Error(`Mailbox verification failed (permanent error): ${error.message.split(': ')[1] || error.message}`);
        } else if (error.message.includes('SMTP authentication error')) {
             throw new Error(`Mailbox verification failed (authentication error): ${error.message.split(': ')[1] || error.message}`);
        } else if (error.message.includes('Connection failed') || error.message.includes('Connection timeout') || error.message.includes('SMTP read timeout') || error.message.includes('TLS handshake failed')) {
             throw new Error(`Mailbox verification failed (connection/timeout): ${error.message}`);
        } else {
             throw new Error(`Mailbox verification failed (unknown SMTP error): ${error.message}`);
        }

    } finally {
        // Always attempt to quit and destroy the socket
        if (socket && !socket.destroyed) {
            try {
                socket.write('QUIT\r\n', () => {
                    setTimeout(() => socket.destroy(), 500); // Give a bit of time for QUIT response
                });
            } catch (cleanupErr) {
                // Ignore errors during cleanup
            }
        }
    }
}


/**
 * Performs a series of validations on a single email.
 * @param {string} email - The email address to validate.
 * @returns {Promise<object>} - An object with validation results.
 */
async function validateSingleEmail(email) {
    const result = {
        email: email,
        isValid: false,
        reason: 'Unknown error.',
        suggestion: null
    };

    if (!email || typeof email !== 'string' || email.trim() === "") {
        result.reason = 'Email is missing, not a string, or empty.';
        return result;
    }

    const cleanedEmail = email.trim().toLowerCase();
    const parts = cleanedEmail.split('@');
    const localPart = parts[0]; // Extract local part
    const domain = parts.length === 2 ? parts[1] : null;

    // --- Core Validation Steps (Sequential, returning early on failure) ---

    // 1. Basic Format Check (Syntax)
    if (!validator.isEmail(cleanedEmail)) {
        result.reason = 'Invalid email format.';
        return result;
    }

    // 2. Domain Part Existence Check
    if (!domain) {
        result.reason = 'Invalid email format: missing domain.';
        return result;
    }

    // 3. Disposable Email Check
    if (disposableDomains.has(domain)) {
        result.reason = 'Disposable email address detected.';
        return result;
    }

    // 4. Blacklisted Domain Check (Custom List)
    if (blacklistedDomains.has(domain)) {
        result.reason = 'Domain is blacklisted by custom policy.';
        return result;
    }

    // 5. MISP Warning List Check (Domains)
    if (mispWarningDomains.has(domain)) {
        result.reason = 'Domain found in MISP warning lists.';
        return result;
    }

    // 6. MISP Warning List Check (Full Email Addresses)
    if (mispWarningEmails.has(cleanedEmail)) {
        result.reason = 'Email address found in MISP warning lists.';
        return result;
    }

    // 7. Word Removal List Check (Optional)
    // FIX: Check only against the localPart, not the entire email
    for (const word of wordRemovalList) {
        if (localPart.includes(word)) { // Changed from cleanedEmail.includes(word)
            result.reason = `Email contains a blacklisted word in the local part: "${word}".`; // More specific reason
            return result;
        }
    }

    // 8. Common Typos/Suggestions
    const mailcheckResult = mailcheck.suggest(cleanedEmail);
    if (mailcheckResult) {
        result.reason = `Potential typo: did you mean ${mailcheckResult.full}?`;
        result.suggestion = mailcheckResult.full;
        return result;
    }

    // 9. Known Providers Optimization (FAST-TRACK)
    // If it's a known, reputable provider, and passes syntax, it's likely valid.
    // We skip all subsequent DNS lookups (NS, MX) and SMTP verification for these.
    if (knownProviders.has(domain)) {
        result.isValid = true;
        result.reason = 'Email is from a known, reputable provider (all advanced checks skipped).';
        return result; // RETURN HERE TO SKIP ALL FURTHER ADVANCED CHECKS
    }

    // --- DNS Checks (Only executed if NOT a known provider) ---

    // 10. Parking Domain Check
    try {
        const nsRecords = await limit(() => new Promise((resolve, reject) => {
            dns.resolveNs(domain, (err, addresses) => {
                if (err) return resolve([]); // Treat DNS errors for NS as no parking detected
                resolve(addresses);
            });
        }));

        const isParked = nsRecords.some(ns => parkingDomainNS.has(ns.toLowerCase()));
        if (isParked) {
            result.reason = 'Domain appears to be parked (no active mail service).';
            return result;
        }
    } catch (error) {
        console.warn(`Warning: NS lookup failed for ${domain}: ${error.message}`);
    }

    // 11. MX Record Existence Check (Still useful to know if the domain *should* receive mail)
    let hasMxRecords = false;
    try {
        await limit(() => new Promise((resolve, reject) => {
            dns.resolveMx(domain, (err, addresses) => {
                if (err) {
                    if (err.code === 'ENOTFOUND' || err.code === 'ENODATA' || err.code === 'NODATA') {
                        result.reason = 'Domain does not exist or has no MX records.';
                    } else {
                        result.reason = `DNS lookup failed for MX records: ${err.message}`;
                    }
                    result.isValid = false;
                    return reject(err); // Propagate DNS errors
                }
                if (addresses && addresses.length > 0) {
                    hasMxRecords = true;
                    resolve();
                } else {
                    result.reason = 'Domain has no MX records configured.';
                    result.isValid = false;
                    resolve();
                }
            });
        }));
    } catch (error) {
        return result; // MX lookup failed, validation stops here
    }

    if (!hasMxRecords) {
        return result; // No MX records found, validation stops here
    }


    // --- SMTP Mailbox Verification (Conditional and High-Risk) ---
    // Only attempt if enabled AND if SMTP_HOST is configured AND if MX records were found
    if (config.enableSmtpVerification && config.smtpHost) {
        let mailboxVerified = false;
        let smtpReason = 'SMTP verification could not complete.';

        try {
            mailboxVerified = await limit(() => checkMailboxExists(cleanedEmail, config.smtpVerificationFromEmail));
            if (mailboxVerified) {
                result.isValid = true;
                result.reason = 'Email appears valid (MX records & Mailbox verified via remote SMTP).';
                return result; // Successfully verified, return immediately
            }
        } catch (error) {
            // console.error(`Failed SMTP check for ${cleanedEmail} via ${config.smtpHost}: ${error.message}`); // Optional: enable for debugging
            smtpReason = error.message; // Capture the last error message
        }
        // If SMTP verification failed after trying
        result.isValid = false;
        result.reason = `Mailbox verification failed via remote SMTP: ${smtpReason}`;
        return result;

    } else {
        // If SMTP verification is disabled or not fully configured (missing SMTP_HOST)
        // but MX records were found, it's considered valid up to this point.
        result.isValid = true;
        result.reason = 'Email appears valid (MX records found, SMTP verification skipped or not configured).';
        return result;
    }

    // This point should theoretically not be reached if all checks return correctly
    return result;
}

/**
 * Validates one or more email addresses concurrently.
 * @param {string|string[]} emails - A single email string or an array of email strings.
 * @returns {Promise<object[]>} - An array of validation results.
 */
async function validateEmails(emails) {
    const emailsToValidate = Array.isArray(emails) ? emails : [emails];
    const validationPromises = emailsToValidate.map(email => validateSingleEmail(email));
    return Promise.all(validationPromises);
}

module.exports = {
    validateEmails
};