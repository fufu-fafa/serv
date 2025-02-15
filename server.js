// Install dependencies: express, mysql2, bcrypt, jsonwebtoken, dotenv, cors
// Run: npm install express mysql2 bcrypt jsonwebtoken dotenv cors

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

app.use(express.json());
app.use(cors());
app.use(express.static('public'));

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
});

db.connect(err => {
    if (err) throw err;
    console.log('Connected to the database.');
});

// Serve the frontend login page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Register User
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ message: 'User registered' });
    });
});

// Login User
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (results.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
        
        const user = results[0];
        const match = await bcrypt.compare(password, user.password);
        
        if (!match) return res.status(401).json({ error: 'Invalid credentials' });
        
        const token = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ token });
    });
});

// Middleware to check authentication
const authenticate = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Unauthorized: No token provided' });

    const token = authHeader.split(' ')[1]; // Extract token

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Unauthorized: Invalid token' });
        req.user = decoded; // Attach user data to request
        next();
    });
};

// Protect `/correct` page
app.get('/correct', authenticate, (req, res) => {
    res.sendFile(path.join(__dirname, 'protected', 'correct.html'));
});


// Serve correct.html only if authenticated
app.get('/correct', authenticate, (req, res) => {
    res.sendFile(path.join(__dirname, 'protected', 'correct.html'));
});

// no caching
app.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    next();
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
