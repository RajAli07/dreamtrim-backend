// "DreamTrip" Application Implementation

// Importing required modules
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

// Initialize the Express app
const app = express();
app.use(express.json());
app.use(cors());

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}, () => console.log('Connected to MongoDB'));

// User Schema and Model
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

// Middleware for Authentication
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.sendStatus(403);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// User Registration
app.post('/register', async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const newUser = new User({
            username: req.body.username,
            email: req.body.email,
            password: hashedPassword
        });
        await newUser.save();
        res.status(201).send('User Registered');
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// User Login
app.post('/login', async (req, res) => {
    const user = await User.findOne({ email: req.body.email });
    if (!user) return res.status(404).send('User not found');

    const isValid = await bcrypt.compare(req.body.password, user.password);
    if (!isValid) return res.status(403).send('Invalid credentials');

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
});

// Travel API Integration Placeholder
app.get('/search', authenticateToken, async (req, res) => {
    // Replace with actual API call (e.g., Expedia)
    res.json({ message: 'Travel search results go here' });
});

// Community Forum Placeholder
app.post('/forum', authenticateToken, async (req, res) => {
    // Save posts/comments (extend with schema and logic)
    res.json({ message: 'Forum functionality coming soon' });
});

// Budget Tracker Placeholder
app.post('/budget', authenticateToken, async (req, res) => {
    // Track expenses logic
    res.json({ message: 'Budget tracker coming soon' });
});

// Travel Blog Placeholder
app.get('/blog', (req, res) => {
    res.json({ message: 'Travel blog articles go here' });
});

// Start the Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
