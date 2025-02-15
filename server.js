require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'supersecretkey';

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.static('public')); // Serve static files from 'public' directory

// Log GET Requests
app.use((req, res, next) => {
    if (req.method === 'GET') {
        console.log(`[GET Request] Path: ${req.path} - Time: ${new Date().toISOString()}`);
    }
    next();
});

// Database Connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
});

db.connect(err => {
    if (err) {
        console.error('Database connection failed:', err);
        process.exit(1); // Exit process if DB connection fails
    }
    console.log('Connected to the database.');
});

// Serve Login Page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Register User
app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        
        db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json({ message: 'User registered successfully' });
        });
    } catch (err) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Login User
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    console.log(`[LOGIN Attempt] Username: ${username} - Time: ${new Date().toISOString()}`);

    db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
        if (err) {
            console.error(`[LOGIN ERROR] Database error: ${err.message}`);
            return res.status(500).json({ error: 'Database error' });
        }
        if (results.length === 0) {
            console.warn(`[LOGIN FAILED] Username: ${username} - Reason: User not found`);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = results[0];
        const match = await bcrypt.compare(password, user.password);

        if (!match) {
            console.warn(`[LOGIN FAILED] Username: ${username} - Reason: Incorrect password`);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: '1h' });
        console.log(`[LOGIN SUCCESS] Username: ${username} - User ID: ${user.id}`);

        res.json({ token });
    });
});

// Authentication Middleware
const authenticate = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.warn(`[AUTH FAILED] No token provided - Path: ${req.path}`);
        return res.status(401).json({ error: 'Unauthorized: No token provided' });
    }

    const token = authHeader.split(' ')[1];

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) {
            console.warn(`[AUTH FAILED] Invalid token - Path: ${req.path}`);
            return res.status(401).json({ error: 'Unauthorized: Invalid token' });
        }

        console.log(`[AUTH SUCCESS] User ID: ${decoded.userId} - Path: ${req.path}`);
        req.user = decoded;
        next();
    });
};

// Serve Correct Page (Protected)
app.get('/correct', authenticate, (req, res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.sendFile(path.join(__dirname, 'protected', 'correct.html'));
});

// Start Server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
