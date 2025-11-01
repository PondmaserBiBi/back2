// server.js
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());
app.use(express.json());

// ==========================
// Supabase config
// ==========================
const SUPABASE_URL = 'https://mtcjhuwygjwxnthwxqsk.supabase.co';
const SUPABASE_KEY = 'YOUR_SUPABASE_KEY'; // แนะนำใช้ environment variable
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// ==========================
// JWT secret
// ==========================
const JWT_SECRET = 'mysecretkey';

// ==========================
// Routes
// ==========================

// Root
app.get('/', (req, res) => res.send('Backend is running ✅'));

// Register
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) 
        return res.status(400).json({ error: 'Missing username or password' });

    try {
        const hashed = bcrypt.hashSync(password, 8);

        const { data, error } = await supabase
            .from('users')
            .insert([{ username, password: hashed }])
            .select(); // <- ใส่ select() เพื่อให้ data คืนค่า array ของ row

        if (error) return res.status(500).json({ error: error.message });
        if (!data || data.length === 0) return res.status(500).json({ error: 'Insert failed' });

        res.json({ message: 'User registered successfully', user: data[0] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) 
        return res.status(400).json({ error: 'Missing username or password' });

    try {
        const { data: users, error } = await supabase
            .from('users')
            .select('*')
            .eq('username', username)
            .limit(1);

        if (error) return res.status(500).json({ error: error.message });
        if (!users || users.length === 0) return res.status(400).json({ error: 'User not found' });

        const user = users[0];
        const valid = bcrypt.compareSync(password, user.password);
        if (!valid) return res.status(401).json({ error: 'Invalid password' });

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ message: 'Login success', token, user: { username: user.username } });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// Protected route
app.get('/protected', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Invalid token' });
        res.json({ message: 'Welcome!', user: decoded });
    });
});

// ==========================
// Start server
// ==========================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
