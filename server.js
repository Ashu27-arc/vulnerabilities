const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const db = require("./db"); // Assume this connects to a database
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

app.use(bodyParser.json());

app.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: "Username and password are required" });
        }

        const user = await db.query("SELECT * FROM users WHERE username = $1", [username]);
        
        if (user.length === 0) {
            return res.status(401).json({ error: "Invalid credentials" });
        }
        
        const isPasswordValid = await bcrypt.compare(password, user[0].password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: "Invalid credentials" });
        }
        
        const token = jwt.sign({ id: user[0].id, username: user[0].username }, process.env.JWT_SECRET, { expiresIn: "1h" });
        res.json({ token });
    } catch (error) {
        res.status(500).json({ error: "Internal server error" });
    }
});

app.post("/register", async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: "Username and password are required" });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        await db.query("INSERT INTO users (username, password) VALUES ($1, $2)", [username, hashedPassword]);
        
        res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
        res.status(500).json({ error: "Internal server error" });
    }
});

const authenticateToken = (req, res, next) => {
    const token = req.header("Authorization");
    if (!token) return res.status(401).json({ error: "Access denied" });
    
    try {
        const verified = jwt.verify(token.replace("Bearer ", ""), process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch (error) {
        res.status(403).json({ error: "Invalid token" });
    }
};

app.get("/protected", authenticateToken, (req, res) => {
    res.json({ message: "This is a protected route", user: req.user });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
