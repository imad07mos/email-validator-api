// src/utils/mispWarningLists.js
const fetch = require('node-fetch'); // Import node-fetch

// Define the URLs for the raw MISP warning lists we want to use.
// You can find more lists at: https://github.com/MISP/misp-warninglists/tree/main/lists
// Choose lists that are most relevant to email validation (domains and email addresses).
const MISP_LIST_URLS = [
    "https://raw.githubusercontent.com/MISP/misp-warninglists/refs/heads/main/lists/parking-domain-ns/list.json",
    "https://raw.githubusercontent.com/MISP/misp-warninglists/refs/heads/main/lists/url-shortener/list.json",
   
    // If there are lists for full email addresses, you can add them too:
    // "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/specific-bad-email-addresses/list.json",
];

// In-memory Sets to store the loaded warning indicators
let mispWarningDomains = new Set();
let mispWarningEmails = new Set(); // For full email addresses, if any lists provide them

/**
 * Fetches and parses MISP warning lists from the defined URLs.
 * Populates mispWarningDomains and mispWarningEmails Sets.
 */
async function loadMispWarningLists() {
    console.log('Attempting to load MISP warning lists...');
    try {
        const tempDomains = new Set();
        const tempEmails = new Set();

        for (const url of MISP_LIST_URLS) {
            try {
                const response = await fetch(url);
                if (!response.ok) {
                    console.warn(`[MISP Loader] Failed to fetch list from ${url}: ${response.statusText}`);
                    continue;
                }
                const data = await response.json();

                if (data && data.list && Array.isArray(data.list)) {
                    data.list.forEach(item => {
                        const lowerCaseItem = item.toLowerCase();
                        if (lowerCaseItem.includes('@')) { // Check if it looks like a full email address
                            tempEmails.add(lowerCaseItem);
                        } else { // Assume it's a domain
                            tempDomains.add(lowerCaseItem);
                        }
                    });
                } else {
                    console.warn(`[MISP Loader] Unexpected data format from ${url}:`, data);
                }
            } catch (fetchError) {
                console.error(`[MISP Loader] Error fetching/parsing ${url}: ${fetchError.message}`);
            }
        }

        // Only update the global sets if all fetches were attempted
        mispWarningDomains = tempDomains;
        mispWarningEmails = tempEmails;

        console.log(`Successfully loaded ${mispWarningDomains.size} warning domains and ${mispWarningEmails.size} warning emails from MISP.`);
    } catch (error) {
        console.error('Critical error during MISP warning list loading process:', error.message);
    }
}

// Call this function immediately when the module is imported.
// This makes the loading asynchronous but doesn't block the main event loop.
// The validator will start using these lists once they are populated.
loadMispWarningLists();

module.exports = {
    mispWarningDomains,
    mispWarningEmails,
    loadMispWarningLists // Export this for potential manual refresh later (e.g., via an admin API endpoint)
};