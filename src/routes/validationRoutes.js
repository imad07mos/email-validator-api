// src/routes/validationRoutes.js
const express = require('express');
const { validateEmails } = require('../services/emailValidator');
const config = require('../config'); // Access config for MAX_EMAILS_PER_REQUEST
const router = express.Router();

router.post('/validate-emails', async (req, res) => {
    let emails = req.body.emails; // Try to get from request body (preferred for arrays)

    // If not found in body, try to get from query parameter as a comma-separated string
    if (!emails && req.query.emails) {
        emails = req.query.emails.split(',').map(email => email.trim());
    }

    if (!emails || (Array.isArray(emails) && emails.length === 0)) {
        return res.status(400).json({
            error: 'Emails field is required. Provide a single email string or an array in the request body, or a comma-separated string in the "emails" query parameter.'
        });
    }

    const emailsArray = Array.isArray(emails) ? emails : [emails];

    if (emailsArray.length > config.maxEmailsPerRequest) {
        return res.status(400).json({ error: `Too many emails. Maximum allowed is ${config.maxEmailsPerRequest}.` });
    }

    try {
        const results = await validateEmails(emailsArray);
        res.json(results);
    } catch (error) {
        console.error('Validation error:', error);
        res.status(500).json({ error: 'An internal server error occurred during validation.' });
    }
});

module.exports = router;