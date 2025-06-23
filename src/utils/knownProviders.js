// src/utils/knownProviders.js
// A list of domains from major, reputable email providers.
// If an email matches one of these domains and passes basic syntax,
// we can often consider it valid without an MX record lookup,
// as these providers almost always have valid MX records and infrastructure.
const knownProviders = new Set([
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "aol.com",
    "protonmail.com",
    "icloud.com",
    "yandex.com",
    "mail.com",
    "gmx.com",
    // Country-specific popular providers:
    "yahoo.fr", "hotmail.fr", "outlook.fr",
    "orange.fr", "laposte.net", "free.fr", "sfr.fr", "live.fr", "wanadoo.fr", "bbox.fr",
    // Add more as needed
]);

module.exports = knownProviders;