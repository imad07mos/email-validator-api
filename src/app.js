// src/app.js
import express from 'express';
import config from './config/index.js';
import validationRoutes from './routes/validationRoutes.js';

const app = express();

// --- Middleware ---

// Health check endpoint (does not require authentication)
app.get('/', (req, res) => {
    res.status(200).send('Email Validator API is running!');
});

// Middleware to parse JSON request bodies
app.use(express.json());

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const providedToken = req.query.token; // Get token from query parameter

    if (!providedToken) {
        return res.status(401).json({ error: 'Authentication token is required.' });
    }

    if (providedToken !== config.apiToken) {
        return res.status(403).json({ error: 'Invalid authentication token.' });
    }

    next(); // If token is valid, proceed to the next middleware/route handler
};

// Apply authentication middleware to all routes under '/api'
app.use('/api', authenticateToken, validationRoutes);

// --- Server Start ---
app.listen(config.port, () => {
    console.log(`Server running on port ${config.port}`);
    console.log(`Access Validation API at http://localhost:${config.port}/api/validate-emails?token=${config.apiToken}`);
});

export default app;
