// src/config/index.js
import 'dotenv/config';

export default {
    port: process.env.PORT || 3000,
    apiToken: process.env.API_TOKEN,
    concurrencyLimit: parseInt(process.env.CONCURRENCY_LIMIT || '5', 10),
    maxEmailsPerRequest: parseInt(process.env.MAX_EMAILS_PER_REQUEST || '100', 10),

    // SMTP Mailbox Verification Settings
    enableSmtpVerification: process.env.ENABLE_SMTP_VERIFICATION === 'true',
    smtpHost: process.env.SMTP_HOST || null, // NEW
    smtpPort: parseInt(process.env.SMTP_PORT || '587', 10), // NEW
    smtpSecurePort: parseInt(process.env.SMTP_SECURE_PORT || '465', 10), // NEW for SMTPS
    smtpEnableSSL: process.env.SMTP_ENABLE_SSL === 'true', // NEW: Option to enable/disable direct SSL/TLS
    smtpVerificationFromEmail: process.env.SMTP_VERIFICATION_FROM_EMAIL || 'noreply@example.com',
    smtpUsername: process.env.SMTP_USERNAME || null,
    smtpPassword: process.env.SMTP_PASSWORD || null,
    smtpConnectTimeoutMs: parseInt(process.env.SMTP_CONNECT_TIMEOUT_MS || '5000', 10),
    smtpReadTimeoutMs: parseInt(process.env.SMTP_READ_TIMEOUT_MS || '5000', 10)
};
