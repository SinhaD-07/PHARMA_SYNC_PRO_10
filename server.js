const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.JWT_SECRET || "pharma_sync_multi_zone_secret_2026";

app.use(cors());
app.use(express.json());

// Initialize SQLite Database
const db = new sqlite3.Database('./pharmacy.db', (err) => {
    if (!err) {
        console.log("Connected to Multi-Zone Cloud Database.");
        initDb();
    }
});

function initDb() {
    // 1. Users Table (Stores Username, Password, Role, Zone, Status)
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT,        -- 'ADMIN' or 'OPERATOR'
        zone TEXT,        -- e.g., 'ZONE-NORTH', 'ZONE-SOUTH', 'MAIN-STORE'
        status INTEGER DEFAULT 1 -- 1 = ON, 0 = OFF
    )`);

    // 2. Entries Table (Stores Live Drug Dispenses per Zone)
    db.run(`CREATE TABLE IF NOT EXISTS dispenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        zone TEXT,
        drug_name TEXT,
        qty INTEGER,
        entered_by TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Create default Master Admin
    db.get("SELECT * FROM users WHERE username = 'admin'", async (err, row) => {
        if (!row) {
            const hash = await bcrypt.hash('admin123', 10);
            db.run("INSERT INTO users (username, password, role, zone, status) VALUES (?, ?, 'ADMIN', 'ALL', 1)", ['admin', hash]);
            console.log("Master Admin created: admin / admin123");
        }
    });
}

// Security Middleware: Verifies Session and Checks if User is Turned ON
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

// --- AUTHENTICATION ROUTE ---

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: "User not found" });
        if (user.status !== 1) return res.status(403).json({ error: "Account is turned OFF. Contact Admin." });

        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) return res.status(400).json({ error: "Invalid Password" });

        const token = jwt.sign({ id: user.id, username: user.username, role: user.role, zone: user.zone }, SECRET_KEY, { expiresIn: '24h' });
        res.json({ token, role: user.role, username: user.username, zone: user.zone });
    });
});

// --- DISPENSE & AUTO-SYNC ROUTES ---

// Record a new drug entry
app.post('/api/dispense', authenticateToken, (req, res) => {
    const { drug_name, qty } = req.body;
    const zone = req.user.role === 'ADMIN' ? (req.body.zone || 'MAIN-STORE') : req.user.zone;

    db.run("INSERT INTO dispenses (zone, drug_name, qty, entered_by) VALUES (?, ?, ?, ?)", 
        [zone, drug_name.toUpperCase(), qty, req.user.username], 
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: "Recorded successfully" });
        }
    );
});

// Fetch Live Entries (Filters data by Zone for Operators, or All for Admin)
app.get('/api/dispense/sync', authenticateToken, (req, res) => {
    let query = "SELECT * FROM dispenses WHERE zone = ? ORDER BY id DESC LIMIT 50";
    let params = [req.user.zone];

    if (req.user.role === 'ADMIN') {
        const filterZone = req.query.zone;
        if (filterZone && filterZone !== 'ALL') {
            query = "SELECT * FROM dispenses WHERE zone = ? ORDER BY id DESC LIMIT 50";
            params = [filterZone];
        } else {
            query = "SELECT * FROM dispenses ORDER BY id DESC LIMIT 100";
            params = [];
        }
    }

    db.all(query, params, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// --- ADMIN CONTROL ROUTES ---

// Get all users across all zones
app.get('/api/users', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required" });
    db.all("SELECT id, username, role, zone, status FROM users", [], (err, rows) => res.json(rows));
});

// Create new user assigned to a Zone
app.post('/api/users', authenticateToken, async (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required" });
    const { username, password, role, zone } = req.body;
    const hash = await bcrypt.hash(password, 10);
    db.run("INSERT INTO users (username, password, role, zone, status) VALUES (?, ?, ?, ?, 1)", 
        [username, hash, role, zone.toUpperCase()], 
        function(err) {
            if (err) return res.status(400).json({ error: "Username already exists" });
            res.json({ message: "User created!" });
        }
    );
});

// Toggle user ON/OFF (Instantly cuts off access on next auto-sync)
app.put('/api/users/:id/status', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required" });
    db.run("UPDATE users SET status = ? WHERE id = ?", [req.body.status, req.params.id], function(err) {
        res.json({ message: "Status updated!" });
    });
});

// Delete user permanently
app.delete('/api/users/:id', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required" });
    db.run("DELETE FROM users WHERE id = ?", [req.params.id], function(err) {
        res.json({ message: "User removed!" });
    });
});

// --- APP INTERFACE (FRONTEND) ---

app.get('/', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHARMA-SYNC PRO | MULTI-ZONE CLOUD</title>
    <style>
        :root { --bg: #0f172a; --card: #1e293b; --text: #f1f5f9; --accent: #4361ee; --danger: #ef4444; --success: #10b981; --border: #334155; }
        body { font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 15px; }
        #loginOverlay { position: fixed; inset: 0; background: var(--bg); display: grid; place-items: center; z-index: 1000; }
        .card { background: var(--card); padding: 20px; border-radius: 12px; border: 1px solid var(--border); box-shadow: 0 10px 25px rgba(0,0,0,0.3); margin-bottom: 15px; }
        .login-box { width: 300px; }
        input, select { width: 100%; padding: 10px; margin-bottom: 10px; box-sizing: border-box; background: var(--bg); color: var(--text); border: 1px solid var(--border); border-radius: 6px; }
        button { width: 100%; padding: 10px; background: var(--accent); color: white; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; }
        button:hover { filter: brightness(1.1); }
        .btn-off { background: var(--danger); }
        .btn-on { background: var(--success); }
        .grid { display: grid; grid-template-columns: 360px 1fr; gap: 20px; }
        @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
        table { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 10px; }
        th, td { padding: 8px; border-bottom: 1px solid var(--border); text-align: left; }
        .admin-section { display: none; }
        .badge { padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 11px; }
        .badge-on { background: #064e3b; color: #34d399; }
        .badge-off { background: #7f1d1d; color: #f87171; }
        .sync-pulse { display: inline-block; width: 8px; height: 8px; background: var(--success); border-radius: 50%; margin-right: 5px; }
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

<!-- TOP BAR -->
<div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid var(--border); padding-bottom:15px; margin-bottom:15px;">
    <div>
        <h1 style="margin:0; font-size:20px; display:inline-block;">PHARMA<span style="color:var(--accent)">SYNC</span></h1>
        <span id="zoneBadge" style="margin-left:10px; background:var(--accent); color:white; padding:3px 8px; border-radius:12px; font-size:11px; font-weight:bold;"></span>
    </div>
    <div style="display:flex; align-items:center;">
        <span style="font-size:12px; margin-right:15px; color:#94a3b8;"><span class="sync-pulse"></span>LIVE AUTO-SYNC</span>
        <span id="uName" style="margin-right:15px; font-weight:bold; color:var(--text);"></span>
        <button onclick="logout()" style="width:auto; padding:6px 12px; background: #64748b;">LOGOUT</button>
    </div>
</div>

<div class="grid">
    <!-- LEFT PANEL: ADMIN USER CONTROL -->
    <div>
        <div id="adminPanel" class="card admin-section">
            <h3 style="margin-top:0; color:var(--success);">👑 Admin Access Control</h3>
            <input type="text" id="newU" placeholder="New Username">
            <input type="password" id="newP" placeholder="New Password">
            <input type="text" id="newZ" placeholder="Assign Zone (e.g., ZONE-A)">
            <select id="newR"><option value="OPERATOR">OPERATOR</option><option value="ADMIN">ADMIN</option></select>
            <button onclick="createUser()" style="background:var(--success);">CREATE USER</button>

            <h4 style="margin-top:20px; margin-bottom:5px;">Users List & Control</h4>
            <div style="max-height:250px; overflow-y:auto;">
                <table>
                    <thead><tr><th>User / Zone</th><th>Status</th><th>Action</th></tr></thead>
                    <tbody id="userList"></tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- RIGHT PANEL: DISPENSE CONSOLE & LIVE SYNC FEED -->
    <div>
        <div class="card">
            <h2>🛒 Record Drug Entry</h2>
            <div style="display:grid; grid-template-columns: 1fr 100px 120px; gap:10px;">
                <input type="text" id="drug" placeholder="Drug Name..." style="margin-bottom:0;">
                <input type="number" id="qty" placeholder="Qty" style="margin-bottom:0;">
                <button style="background:var(--success);" onclick="recordEntry()">RECORD</button>
            </div>
        </div>

        <div class="card">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <h2 style="margin:0;">📊 Live Zone Feed (Auto-Syncs Every 3s)</h2>
                <div id="adminZoneFilter" style="display:none;">
                    <select id="filterZoneSelect" onchange="syncData()" style="margin-bottom:0; padding:5px; font-size:12px;">
                        <option value="ALL">All Zones Overview</option>
                    </select>
                </div>
            </div>
            
            <table>
                <thead>
                    <tr><th>Time</th><th>Zone</th><th>Drug Name</th><th>Qty</th><th>Entered By</th></tr>
                </thead>
                <tbody id="dispenseLog"></tbody>
            </table>
        </div>
    </div>
</div>

<script>
    let token = localStorage.getItem('p_token'), role = localStorage.getItem('p_role'), user = localStorage.getItem('p_user'), zone = localStorage.getItem('p_zone');

    async function login() {
        const u = document.getElementById('loginUser').value, p = document.getElementById('loginPass').value;
        const res = await fetch('/api/login', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({username: u, password: p}) });
        const d = await res.json();
        if(res.ok) {
            localStorage.setItem('p_token', d.token); localStorage.setItem('p_role', d.role); 
            localStorage.setItem('p_user', d.username); localStorage.setItem('p_zone', d.zone);
            location.reload();
        } else { document.getElementById('errMsg').innerText = d.error; }
    }

    function logout() { localStorage.clear(); location.reload(); }

    async function recordEntry() {
        const d = document.getElementById('drug').value, q = document.getElementById('qty').value;
        if(!d || !q) return alert("Enter drug name and quantity");

        const res = await fetch('/api/dispense', {
            method: 'POST',
            headers: {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'},
            body: JSON.stringify({ drug_name: d, qty: parseInt(q) })
        });

        if(res.ok) {
            document.getElementById('drug').value = ''; document.getElementById('qty').value = '';
            syncData(); // Instant local sync
        }
    }

    // REAL-TIME AUTO SYNC ENGINE (Runs every 3 seconds)
    async function syncData() {
        if(!token) return;

        let url = '/api/dispense/sync';
        if(role === 'ADMIN') {
            const selectedFilter = document.getElementById('filterZoneSelect').value;
            url += '?zone=' + selectedFilter;
        }

        const res = await fetch(url, { headers: {'Authorization': 'Bearer ' + token} });
        const data = await res.json();

        // INSTANT ACCESS REVOCATION
        if(res.status === 403 && data.error === 'ACCOUNT_DISABLED') {
            alert("Your access has been turned OFF by the Administrator.");
            logout();
            return;
        }

        if(res.ok) {
            document.getElementById('dispenseLog').innerHTML = data.map(i => \`
                <tr>
                    <td>\${new Date(i.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</td>
                    <td><b style="color:var(--accent)">\${i.zone}</b></td>
                    <td><b>\${i.drug_name}</b></td>
                    <td><span class="badge badge-on">\${i.qty}</span></td>
                    <td>\${i.entered_by}</td>
                </tr>
            \`).join('');
        }
    }

    async function loadUsers() {
        const res = await fetch('/api/users', { headers: {'Authorization': 'Bearer ' + token} });
        const data = await res.json();
        if(res.ok) {
            document.getElementById('userList').innerHTML = data.map(u => \`
                <tr>
                    <td><b>\${u.username}</b><br><small style="color:#94a3b8">\${u.zone}</small></td>
                    <td><span class="badge \${u.status ? 'badge-on':'badge-off'}">\${u.status ? 'ON':'OFF'}</span></td>
                    <td>
                        \${u.username !== 'admin' ? \`
                            <button class="\${u.status ? 'btn-off':'btn-on'}" style="padding:4px 6px; font-size:10px; width:auto;" onclick="toggleUser(\${u.id}, \${u.status ? 0 : 1})">\${u.status ? 'OFF':'ON'}</button>
                            <button class="btn-off" style="padding:4px 6px; font-size:10px; width:auto;" onclick="deleteUser(\${u.id})">X</button>
                        \` : ''}
                    </td>
                </tr>
            \`).join('');

            // Populate Admin Zone Filter Dropdown
            const zones = [...new Set(data.map(u => u.zone))].filter(z => z !== 'ALL');
            const filterSelect = document.getElementById('filterZoneSelect');
            filterSelect.innerHTML = '<option value="ALL">All Zones Overview</option>' + zones.map(z => \`<option value="\${z}">\${z}</option>\`).join('');
        }
    }

    async function createUser() {
        const u = document.getElementById('newU').value, p = document.getElementById('newP').value, z = document.getElementById('newZ').value, r = document.getElementById('newR').value;
        if(!u || !p || !z) return alert("Fill in username, password, and zone");
        await fetch('/api/users', { method: 'POST', headers: {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}, body: JSON.stringify({username: u, password: p, zone: z, role: r}) });
        document.getElementById('newU').value = ''; document.getElementById('newP').value = ''; document.getElementById('newZ').value = '';
        loadUsers();
    }

    async function toggleUser(id, status) {
        await fetch(\`/api/users/\${id}/status\`, { method: 'PUT', headers: {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}, body: JSON.stringify({status}) });
        loadUsers();
    }

    async function deleteUser(id) {
        if(confirm("Remove user permanently?")) {
            await fetch(\`/api/users/\${id}\`, { method: 'DELETE', headers: {'Authorization': 'Bearer ' + token} });
            loadUsers();
        }
    }

    // INITIALIZATION
    if(token) {
        document.getElementById('loginOverlay').style.display = 'none';
        document.getElementById('uName').innerText = user;
        document.getElementById('zoneBadge').innerText = zone;

        if(role === 'ADMIN') {
            document.getElementById('adminPanel').style.display = 'block';
            document.getElementById('adminZoneFilter').style.display = 'block';
            loadUsers();
        }

        syncData();
        setInterval(syncData, 3000); // AUTO-SYNC EVERY 3 SECONDS
    }
</script>
</body>
</html>
    `);
});

app.listen(PORT, () => console.log(`Multi-Zone Server running on port ${PORT}`));
