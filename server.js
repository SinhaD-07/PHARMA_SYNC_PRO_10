const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.JWT_SECRET || "pharma_sync_cloud_secret_key_2026";

app.use(cors());
app.use(express.json());

// Initialize SQLite Database
const db = new sqlite3.Database('./pharmacy.db', (err) => {
    if (!err) {
        console.log("Connected to Cloud Database.");
        initDb();
    }
});

function initDb() {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT,
        status INTEGER DEFAULT 1
    )`);

    // Create default Master Admin
    db.get("SELECT * FROM users WHERE username = 'admin'", async (err, row) => {
        if (!row) {
            const hash = await bcrypt.hash('admin123', 10);
            db.run("INSERT INTO users (username, password, role, status) VALUES (?, ?, 'ADMIN', 1)", ['admin', hash]);
            console.log("Master Admin initialized: admin / admin123");
        }
    });
}

// Middleware to verify JWT token & Active Status
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Access Denied" });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(403).json({ error: "Invalid Session" });

        db.get("SELECT * FROM users WHERE id = ?", [decoded.id], (err, user) => {
            if (err || !user) return res.status(404).json({ error: "User not found" });
            if (user.status !== 1) {
                return res.status(403).json({ error: "ACCOUNT_DISABLED", message: "Your access has been turned OFF by the Administrator." });
            }
            req.user = user;
            next();
        });
    });
};

// --- API ENDPOINTS ---

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: "User not found" });
        if (user.status !== 1) return res.status(403).json({ error: "Account is turned OFF. Contact Admin." });

        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) return res.status(400).json({ error: "Invalid Password" });

        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, SECRET_KEY, { expiresIn: '24h' });
        res.json({ token, role: user.role, username: user.username });
    });
});

app.get('/api/users', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required" });
    db.all("SELECT id, username, role, status FROM users", [], (err, rows) => res.json(rows));
});

app.post('/api/users', authenticateToken, async (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required" });
    const { username, password, role } = req.body;
    const hash = await bcrypt.hash(password, 10);
    db.run("INSERT INTO users (username, password, role, status) VALUES (?, ?, ?, 1)", [username, hash, role], function(err) {
        if (err) return res.status(400).json({ error: "Username already exists" });
        res.json({ message: "User created!" });
    });
});

app.put('/api/users/:id/status', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required" });
    db.run("UPDATE users SET status = ? WHERE id = ?", [req.body.status, req.params.id], function(err) {
        res.json({ message: "Status updated!" });
    });
});

app.delete('/api/users/:id', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required" });
    db.run("DELETE FROM users WHERE id = ?", [req.params.id], function(err) {
        res.json({ message: "User removed!" });
    });
});

// --- SERVE THE APP INTERFACE ---

app.get('/', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHARMA-SYNC PRO | ONLINE ADMIN CONSOLE</title>
    <style>
        :root { --bg: #0f172a; --card: #1e293b; --text: #f1f5f9; --accent: #4361ee; --danger: #ef4444; --success: #10b981; --border: #334155; }
        body { font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 20px; }
        #loginOverlay { position: fixed; inset: 0; background: var(--bg); display: grid; place-items: center; z-index: 1000; }
        .card { background: var(--card); padding: 30px; border-radius: 12px; border: 1px solid var(--border); box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
        .login-box { width: 300px; }
        input, select { width: 100%; padding: 10px; margin-bottom: 10px; box-sizing: border-box; background: var(--bg); color: var(--text); border: 1px solid var(--border); border-radius: 6px; }
        button { width: 100%; padding: 10px; background: var(--accent); color: white; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; }
        button:hover { filter: brightness(1.1); }
        .btn-off { background: var(--danger); }
        .btn-on { background: var(--success); }
        .grid { display: grid; grid-template-columns: 360px 1fr; gap: 20px; margin-top: 20px; }
        @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
        table { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 10px; }
        th, td { padding: 8px; border-bottom: 1px solid var(--border); text-align: left; }
        .admin-section { display: none; }
        .badge { padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 11px; }
        .badge-on { background: #064e3b; color: #34d399; }
        .badge-off { background: #7f1d1d; color: #f87171; }
    </style>
</head>
<body>

<div id="loginOverlay">
    <div class="card login-box">
        <h2 style="text-align:center; color:var(--accent); margin-top:0;">PHARMA-SYNC</h2>
        <input type="text" id="loginUser" placeholder="Username">
        <input type="password" id="loginPass" placeholder="Password">
        <button onclick="login()">LOG IN</button>
        <p id="errMsg" style="color:var(--danger); font-size:12px; text-align:center; margin-bottom:0; margin-top:10px;"></p>
    </div>
</div>

<div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid var(--border); padding-bottom:15px;">
    <h1 style="margin:0; font-size:22px;">PHARMA<span style="color:var(--accent)">SYNC</span> PRO</h1>
    <div>
        <span id="uName" style="margin-right:15px; font-weight:bold; color:var(--accent);"></span>
        <button onclick="logout()" style="width:auto; padding:6px 12px; background: #64748b;">LOGOUT</button>
    </div>
</div>

<div class="grid">
    <div>
        <div id="adminPanel" class="card admin-section">
            <h3 style="margin-top:0; color:var(--success);">👑 Admin Access Control</h3>
            <input type="text" id="newU" placeholder="New Username">
            <input type="password" id="newP" placeholder="New Password">
            <select id="newR"><option value="OPERATOR">OPERATOR</option><option value="ADMIN">ADMIN</option></select>
            <button onclick="createUser()" style="background:var(--success);">CREATE USER</button>

            <h4 style="margin-top:20px; margin-bottom:5px;">User Accounts & Status</h4>
            <table>
                <thead><tr><th>User</th><th>Status</th><th>Control</th></tr></thead>
                <tbody id="userList"></tbody>
            </table>
        </div>
    </div>

    <div class="card">
        <h2>🛒 Dispense Console</h2>
        <p style="color:#94a3b8; font-size:14px;">Live dispensing dashboard connected to cloud database.</p>
        <div style="display:flex; gap:10px;">
            <input type="text" id="drug" placeholder="Drug Name...">
            <input type="number" id="qty" placeholder="Qty" style="width:100px;">
            <button style="width:120px; background:var(--success);" onclick="alert('Entry Recorded!')">RECORD</button>
        </div>
    </div>
</div>

<script>
    let token = localStorage.getItem('pharma_token'), role = localStorage.getItem('pharma_role'), user = localStorage.getItem('pharma_user');

    async function login() {
        const u = document.getElementById('loginUser').value, p = document.getElementById('loginPass').value;
        const res = await fetch('/api/login', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({username: u, password: p}) });
        const d = await res.json();
        if(res.ok) {
            localStorage.setItem('pharma_token', d.token); localStorage.setItem('pharma_role', d.role); localStorage.setItem('pharma_user', d.username);
            location.reload();
        } else { document.getElementById('errMsg').innerText = d.error; }
    }

    function logout() { localStorage.clear(); location.reload(); }

    async function loadUsers() {
        const res = await fetch('/api/users', { headers: {'Authorization': 'Bearer ' + token} });
        const data = await res.json();
        
        if(res.status === 403 && data.error === 'ACCOUNT_DISABLED') {
            alert("Your account was turned OFF by the Administrator."); 
            logout(); 
            return;
        }

        if(res.ok) {
            document.getElementById('userList').innerHTML = data.map(u => \`
                <tr>
                    <td><b>\${u.username}</b> (\${u.role})</td>
                    <td><span class="badge \${u.status ? 'badge-on':'badge-off'}">\${u.status ? 'ACTIVE':'OFF'}</span></td>
                    <td>
                        \${u.username !== 'admin' ? \`
                            <button class="\${u.status ? 'btn-off':'btn-on'}" style="padding:4px 8px; font-size:11px; width:auto;" onclick="toggleUser(\${u.id}, \${u.status ? 0 : 1})">\${u.status ? 'Turn OFF':'Turn ON'}</button>
                            <button class="btn-off" style="padding:4px 8px; font-size:11px; width:auto;" onclick="deleteUser(\${u.id})">Del</button>
                        \` : ''}
                    </td>
                </tr>
            \`).join('');
        }
    }

    async function createUser() {
        const u = document.getElementById('newU').value, p = document.getElementById('newP').value, r = document.getElementById('newR').value;
        if(!u || !p) return alert("Enter username and password");
        await fetch('/api/users', { method: 'POST', headers: {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}, body: JSON.stringify({username: u, password: p, role: r}) });
        document.getElementById('newU').value = ''; document.getElementById('newP').value = ''; loadUsers();
    }

    async function toggleUser(id, status) {
        await fetch(\`/api/users/\${id}/status\`, { method: 'PUT', headers: {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}, body: JSON.stringify({status}) });
        loadUsers();
    }

    async function deleteUser(id) {
        if(confirm("Delete this user permanently?")) {
            await fetch(\`/api/users/\${id}\`, { method: 'DELETE', headers: {'Authorization': 'Bearer ' + token} });
            loadUsers();
        }
    }

    if(token) {
        document.getElementById('loginOverlay').style.display = 'none';
        document.getElementById('uName').innerText = user + \` (\${role})\`;
        if(role === 'ADMIN') {
            document.getElementById('adminPanel').style.display = 'block';
            loadUsers();
        }
    }
</script>
</body>
</html>
    `);
});

app.listen(PORT, () => console.log(`Pharma-Sync Server running on port ${PORT}`));