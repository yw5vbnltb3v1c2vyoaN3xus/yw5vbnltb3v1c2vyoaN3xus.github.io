const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// In-memory user store (Replace with DB for production)
const users = []; 
const JWT_SECRET = "NEXUS_SUPER_SECRET_REPLACE_THIS"; // Move to .env

// --- REGISTRATION ENDPOINT ---
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // 1. Validation: 12+ chars, upper, lower, number, symbol
        const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/;
        if (!strongPasswordRegex.test(password)) {
            return res.status(400).json({ error: "Password does not meet NEXUS security requirements." });
        }

        // 2. Check if user exists
        if (users.find(u => u.username === username)) {
            return res.status(400).json({ error: "Identity already exists." });
        }

        // 3. Hash password
        const hashedPassword = await bcrypt.hash(password, 12);

        // 4. Save User
        const newUser = { id: Date.now(), username, email, password: hashedPassword };
        users.push(newUser);

        res.status(201).json({ success: "Account encrypted and created." });
    } catch (err) {
        res.status(500).json({ error: "System error during registration." });
    }
});

// --- LOGIN ENDPOINT ---
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ error: "Invalid credentials." });
    }

    // Generate JWT
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '2h' });
    
    res.json({ success: true, token });
});
