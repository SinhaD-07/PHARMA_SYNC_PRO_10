const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.JWT_SECRET || "pharma_sync_pro_ultra_secret_2026";

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Database Initialization
const db = new sqlite3.Database('./pharmacy.db', (err) => {
    if (!err) {
        console.log("Connected to Pharma-Sync Multi-Zone Database.");
        initDb();
    }
});

function initDb() {
    // 1. Users
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT,        -- 'ADMIN' or 'OPERATOR'
        zone TEXT,        -- e.g., 'ZONE-NORTH', 'MAIN-STORE'
        status INTEGER DEFAULT 1
    )`);

    // 2. Master Drugs Directory
    db.run(`CREATE TABLE IF NOT EXISTS master_drugs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        drug_name TEXT UNIQUE
    )`);

    // 3. Dispense Records
    db.run(`CREATE TABLE IF NOT EXISTS dispenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        zone TEXT,
        drug_name TEXT,
        qty INTEGER,
        entered_by TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // 4. User Audit Logs (Login / Logout Tracking)
    db.run(`CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        zone TEXT,
        action TEXT, -- 'LOGIN' or 'LOGOUT'
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Default Master Admin Setup
    db.get("SELECT * FROM users WHERE username = 'admin'", async (err, row) => {
        if (!row) {
            const hash = await bcrypt.hash('admin123', 10);
            db.run("INSERT INTO users (username, password, role, zone, status) VALUES ('admin', ?, 'ADMIN', 'ALL', 1)", [hash]);
            console.log("Master Admin initialized: admin / admin123");
        }
    });
}

// Security Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Access Denied" });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(403).json({ error: "Invalid Session" });

        db.get("SELECT * FROM users WHERE id = ?", [decoded.id], (err, user) => {
            if (err || !user) return res.status(404).json({ error: "User not found" });
            if (user.status !== 1) {
                return res.status(403).json({ error: "ACCOUNT_DISABLED", message: "Access turned OFF by Admin." });
            }
            req.user = user;
            next();
        });
    });
};

// --- AUTHENTICATION ROUTES ---

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: "User not found" });
        if (user.status !== 1) return res.status(403).json({ error: "Account is turned OFF." });

        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) return res.status(400).json({ error: "Invalid Password" });

        // Log Login Audit
        db.run("INSERT INTO audit_logs (username, zone, action) VALUES (?, ?, 'LOGIN')", [user.username, user.zone]);

        const token = jwt.sign({ id: user.id, username: user.username, role: user.role, zone: user.zone }, SECRET_KEY, { expiresIn: '24h' });
        res.json({ token, role: user.role, username: user.username, zone: user.zone });
    });
});

app.post('/api/logout', authenticateToken, (req, res) => {
    db.run("INSERT INTO audit_logs (username, zone, action) VALUES (?, ?, 'LOGOUT')", [req.user.username, req.user.zone]);
    res.json({ message: "Logged out successfully" });
});

// --- MASTER DRUG DIRECTORY ROUTES ---

app.get('/api/master-drugs', authenticateToken, (req, res) => {
    db.all("SELECT drug_name FROM master_drugs ORDER BY drug_name ASC", [], (err, rows) => {
        res.json(rows.map(r => r.drug_name));
    });
});

app.post('/api/master-drugs', authenticateToken, (req, res) => {
    const name = req.body.drug_name.trim().toUpperCase();
    db.run("INSERT OR IGNORE INTO master_drugs (drug_name) VALUES (?)", [name], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Drug registered" });
    });
});

app.delete('/api/master-drugs/:name', authenticateToken, (req, res) => {
    db.run("DELETE FROM master_drugs WHERE drug_name = ?", [req.params.name], function(err) {
        res.json({ message: "Drug deleted" });
    });
});

// --- DISPENSE & AUTO-SYNC ROUTES ---

app.post('/api/dispense', authenticateToken, (req, res) => {
    const { drug_name, qty } = req.body;
    const drugName = drug_name.trim().toUpperCase();
    const zone = req.user.role === 'ADMIN' ? (req.body.zone || 'MAIN-STORE') : req.user.zone;

    db.run("INSERT INTO dispenses (zone, drug_name, qty, entered_by) VALUES (?, ?, ?, ?)", 
        [zone, drugName, qty, req.user.username], 
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: "Entry recorded" });
        }
    );
});

app.get('/api/dispense/sync', authenticateToken, (req, res) => {
    let query = "SELECT * FROM dispenses WHERE zone = ? ORDER BY id DESC LIMIT 100";
    let params = [req.user.zone];

    if (req.user.role === 'ADMIN') {
        const filterZone = req.query.zone;
        if (filterZone && filterZone !== 'ALL') {
            query = "SELECT * FROM dispenses WHERE zone = ? ORDER BY id DESC LIMIT 100";
            params = [filterZone];
        } else {
            query = "SELECT * FROM dispenses ORDER BY id DESC LIMIT 200";
            params = [];
        }
    }

    db.all(query, params, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.delete('/api/dispense/:id', authenticateToken, (req, res) => {
    db.run("DELETE FROM dispenses WHERE id = ?", [req.params.id], function(err) {
        res.json({ message: "Record deleted" });
    });
});

// --- ADMIN AUDIT & USER CONTROL ROUTES ---

app.get('/api/users', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required" });
    
    // Returns users + total entries recorded by each user
    const sql = `
        SELECT u.id, u.username, u.role, u.zone, u.status, 
               COUNT(d.id) as total_entries, 
               COALESCE(SUM(d.qty), 0) as total_qty
        FROM users u 
        LEFT JOIN dispenses d ON u.username = d.entered_by 
        GROUP BY u.id
    `;
    db.all(sql, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/users', authenticateToken, async (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required" });
    const { username, password, role, zone } = req.body;
    const hash = await bcrypt.hash(password, 10);
    db.run("INSERT INTO users (username, password, role, zone, status) VALUES (?, ?, ?, ?, 1)", 
        [username, hash, role, zone.toUpperCase()], 
        function(err) {
            if (err) return res.status(400).json({ error: "Username already exists" });
            res.json({ message: "User created" });
        }
    );
});

app.put('/api/users/:id/status', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required" });
    db.run("UPDATE users SET status = ? WHERE id = ?", [req.body.status, req.params.id], function(err) {
        res.json({ message: "Status updated" });
    });
});

app.get('/api/admin/audit-logs', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required" });
    db.all("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 50", [], (err, rows) => {
        res.json(rows);
    });
});

// --- FRONTEND APP INTERFACE ---

app.get('/', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHARMA-SYNC PRO | SMART FOCUS</title>
    <meta name="author" content="Debanjan Singha">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.23/jspdf.plugin.autotable.min.js"></script>
    <style>
        :root {
            --bg: #0f172a;
            --sidebar: #1e293b;
            --card-bg: #1e293b;
            --card-inner: #0f172a;
            --accent: #38bdf8;
            --accent-hover: #0284c7;
            --success: #10b981;
            --danger: #f43f5e;
            --warning: #f59e0b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --border: #334155;
        }

        body { font-family: 'Inter', system-ui, -apple-system, sans-serif; background-color: var(--bg); color: var(--text-main); margin: 0; padding: 20px; }
        .container { max-width: 1500px; margin: auto; }

        .app-grid { display: grid; grid-template-columns: 320px 1fr 380px; gap: 20px; align-items: start; }
        @media (max-width: 1200px) { .app-grid { grid-template-columns: 1fr 1fr; } }
        @media (max-width: 800px) { .app-grid { grid-template-columns: 1fr; } }

        .header-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; background: var(--sidebar); padding: 15px 25px; border-radius: 12px; border: 1px solid var(--border); }
        .panel { background: var(--card-bg); padding: 20px; border-radius: 12px; border: 1px solid var(--border); margin-bottom: 20px; }
        .panel h2 { font-size: 14px; margin-top: 0; margin-bottom: 15px; color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: 10px; text-transform: uppercase; letter-spacing: 0.5px; display: flex; justify-content: space-between; align-items: center; }

        input, select { width: 100%; padding: 10px 12px; border: 1px solid var(--border); border-radius: 8px; font-size: 13px; box-sizing: border-box; margin-bottom: 10px; background: var(--card-inner); color: var(--text-main); }
        input:focus, select:focus { outline: 1px solid var(--accent); }
        
        .primary-btn { background: var(--accent); color: #0f172a; padding: 10px; border: none; border-radius: 8px; cursor: pointer; font-weight: 700; width: 100%; transition: 0.2s; font-size: 13px; }
        .primary-btn:hover { background: var(--accent-hover); color: white; }

        .qty-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 6px; margin-bottom: 10px; }
        .qty-pill { background: var(--card-inner); border: 1px solid var(--border); color: var(--text-main); padding: 8px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: bold; }
        .qty-pill:hover { background: var(--accent); color: #0f172a; }

        .table-wrap { max-height: 380px; overflow-y: auto; border: 1px solid var(--border); border-radius: 6px; background: var(--card-inner); }
        table { width: 100%; border-collapse: collapse; font-size: 12px; }
        th { background: #1e293b; padding: 10px; text-align: left; color: var(--text-muted); position: sticky; top: 0; z-index: 10; border-bottom: 1px solid var(--border); }
        td { padding: 8px 10px; border-bottom: 1px solid var(--border); }

        .badge { background: #0284c7; color: white; padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 11px; }
        .badge-on { background: #064e3b; color: #34d399; }
        .badge-off { background: #881337; color: #fda4af; }
        .action-btn { cursor: pointer; font-size: 10px; font-weight: bold; border: none; padding: 4px 8px; border-radius: 4px; }

        #loginOverlay { position: fixed; inset: 0; background: var(--bg); display: grid; place-items: center; z-index: 2000; }
        .login-box { width: 320px; background: var(--card-bg); padding: 30px; border-radius: 12px; border: 1px solid var(--border); }

        .panel-credit { margin-top: 15px; padding-top: 10px; border-top: 1px dashed var(--border); font-size: 11px; color: var(--text-muted); text-align: center; }
        .sync-dot { display: inline-block; width: 8px; height: 8px; background: var(--success); border-radius: 50%; margin-right: 6px; }
    </style>
</head>
<body>

<!-- LOGIN MODAL -->
<div id="loginOverlay">
    <div class="login-box">
        <h2 style="text-align:center; color:var(--accent); margin-top:0;">PHARMA<span style="color:white">SYNC</span></h2>
        <input type="text" id="loginUser" placeholder="Username">
        <input type="password" id="loginPass" placeholder="Password">
        <button class="primary-btn" onclick="login()">LOG IN</button>
        <p id="errMsg" style="color:var(--danger); font-size:12px; text-align:center; margin-top:10px; margin-bottom:0;"></p>
    </div>
</div>

<div class="container">
    <!-- TOP HEADER -->
    <div class="header-bar">
        <div>
            <h1 style="margin:0; font-size:20px; color:white; display:inline-block;">PHARMA<span style="color:var(--accent)">SYNC</span> PRO</h1>
            <span id="zoneBadge" class="badge" style="margin-left:10px;">ZONE</span>
        </div>
        <div style="display:flex; align-items:center; gap:12px;">
            <span style="font-size:12px; color:var(--text-muted);"><span class="sync-dot"></span>LIVE AUTO-SYNC</span>
            <span id="uName" style="font-weight:bold; color:var(--text-main);"></span>
            <button onclick="exportBackup()" style="background:#6366f1; color:white; border:none; padding:8px 12px; border-radius:6px; cursor:pointer; font-weight:bold; font-size:12px;">💾 BACKUP</button>
            <button onclick="logout()" style="background:var(--danger); color:white; border:none; padding:8px 12px; border-radius:6px; cursor:pointer; font-weight:bold; font-size:12px;">LOGOUT</button>
        </div>
    </div>

    <div class="app-grid">
        <!-- LEFT COLUMN: MASTER DIRECTORY & ADMIN USER MONITOR -->
        <div>
            <!-- ADMIN ACCESS CONTROL (VISIBLE TO ADMIN ONLY) -->
            <div id="adminPanel" class="panel" style="display:none;">
                <h2>👑 Admin Access & User Tracking</h2>
                <input type="text" id="newU" placeholder="New Username">
                <input type="password" id="newP" placeholder="New Password">
                <input type="text" id="newZ" placeholder="Assign Zone (e.g., ER-WARD)">
                <select id="newR"><option value="OPERATOR">OPERATOR</option><option value="ADMIN">ADMIN</option></select>
                <button class="primary-btn" style="background:var(--success); color:white; margin-bottom:15px;" onclick="createUser()">CREATE USER</button>

                <h3 style="font-size:12px; color:var(--text-muted); margin-bottom:5px;">User Activity Stats</h3>
                <div class="table-wrap" style="max-height: 180px;">
                    <table>
                        <thead><tr><th>User/Zone</th><th>Entries</th><th>Status</th><th>Action</th></tr></thead>
                        <tbody id="adminUserList"></tbody>
                    </table>
                </div>

                <h3 style="font-size:12px; color:var(--text-muted); margin-top:15px; margin-bottom:5px;">Login/Logout Audit Log</h3>
                <div class="table-wrap" style="max-height: 150px;">
                    <table>
                        <thead><tr><th>Time</th><th>User</th><th>Action</th></tr></thead>
                        <tbody id="auditLogBody"></tbody>
                    </table>
                </div>
            </div>

            <!-- MASTER DRUG DIRECTORY -->
            <div class="panel">
                <h2>📦 Master Directory</h2>
                <input type="text" id="newDrugName" placeholder="New drug name..." onkeydown="if(event.key==='Enter') registerDrug()">
                <button class="primary-btn" onclick="registerDrug()">REGISTER DRUG</button>
                <input type="text" style="margin-top:15px" onkeyup="filterTable('masterBody', this.value)" placeholder="Search directory...">
                <div class="table-wrap" style="max-height:220px;">
                    <table>
                        <tbody id="masterBody"></tbody>
                    </table>
                </div>
                
                <div class="panel-credit">
                    © 2026 <b>Debanjan Singha</b><br>
                    System Architect & Lead Developer
                </div>
            </div>
        </div>

        <!-- CENTER COLUMN: DISPENSE CONSOLE & DAILY TOTALS -->
        <div class="panel">
            <h2>🛒 Dispense Console</h2>
            <div style="display: grid; grid-template-columns: 1fr 100px; gap: 10px;">
                <input type="text" id="searchDrug" list="drugList" placeholder="Select Drug..." onkeydown="if(event.key==='Enter') document.getElementById('dispenseAmount').focus()">
                <input type="number" id="dispenseAmount" placeholder="Qty" onkeydown="if(event.key==='Enter') dispenseDrug()">
            </div>
            <datalist id="drugList"></datalist>

            <div class="qty-grid">
                <button class="qty-pill" onclick="setQty(1)">1</button>
                <button class="qty-pill" onclick="setQty(5)">5</button>
                <button class="qty-pill" onclick="setQty(10)">10</button>
                <button class="qty-pill" onclick="setQty(15)">15</button>
                <button class="qty-pill" onclick="setQty(20)">20</button>
                <button class="qty-pill" onclick="setQty(30)">30</button>
                <button class="qty-pill" onclick="setQty(60)">60</button>
                <button class="qty-pill" onclick="setQty(120)">120</button>
            </div>
            <button class="primary-btn" style="background:var(--success); color:white; height:42px; font-size:15px;" id="recordBtn" onclick="dispenseDrug()">RECORD ENTRY</button>

            <h2 style="margin-top:25px;">📊 Today's Cumulative Totals</h2>
            <input type="text" onkeyup="filterTable('dailyBody', this.value)" placeholder="Filter totals...">
            <div class="table-wrap" style="max-height: 280px;">
                <table>
                    <thead><tr><th>Drug Name</th><th>Total Quantity</th></tr></thead>
                    <tbody id="dailyBody"></tbody>
                </table>
            </div>
        </div>

        <!-- RIGHT COLUMN: LIVE RECENT HISTORY & PDF REPORTING -->
        <div>
            <div class="panel">
                <h2>
                    <span>🕒 Live Zone Feed</span>
                    <select id="filterZoneSelect" onchange="syncData()" style="width:auto; margin-bottom:0; padding:2px 5px; font-size:11px; display:none;">
                        <option value="ALL">All Zones</option>
                    </select>
                </h2>
                <div class="table-wrap" style="max-height: 320px;">
                    <table>
                        <thead><tr><th>Time</th><th>Details</th><th>By</th><th></th></tr></thead>
                        <tbody id="historyBody"></tbody>
                    </table>
                </div>
            </div>

            <div class="panel">
                <h2>📄 Report Generation</h2>
                <input type="text" id="pdfRemarks" placeholder="Enter report remarks (Mandatory)...">
                <button class="primary-btn" style="background:var(--danger); color:white;" onclick="generateReport()">GENERATE PDF REPORT</button>
            </div>
        </div>
    </div>
</div>

<script>
    let token = localStorage.getItem('p_token'), 
        role = localStorage.getItem('p_role'), 
        user = localStorage.getItem('p_user'), 
        zone = localStorage.getItem('p_zone');

    let masterList = [];
    let liveDispenseLog = [];
    let dailyTotals = {};

    // AUTHENTICATION
    async function login() {
        const u = document.getElementById('loginUser').value, p = document.getElementById('loginPass').value;
        const res = await fetch('/api/login', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({username: u, password: p}) });
        const d = await res.json();
        if(res.ok) {
            localStorage.setItem('p_token', d.token); 
            localStorage.setItem('p_role', d.role); 
            localStorage.setItem('p_user', d.username); 
            localStorage.setItem('p_zone', d.zone);
            location.reload();
        } else { 
            document.getElementById('errMsg').innerText = d.error; 
        }
    }

    async function logout() { 
        if(token) {
            await fetch('/api/logout', { method: 'POST', headers: {'Authorization': 'Bearer ' + token} });
        }
        localStorage.clear(); 
        location.reload(); 
    }

    // MASTER DIRECTORY MANAGEMENT
    async function loadMasterDrugs() {
        const res = await fetch('/api/master-drugs', { headers: {'Authorization': 'Bearer ' + token} });
        if(res.ok) {
            masterList = await res.json();
            document.getElementById('masterBody').innerHTML = masterList.map(item => \`
                <tr>
                    <td><b>\${item}</b></td>
                    <td style="text-align:right">
                        <button class="action-btn" style="background:var(--danger); color:white;" onclick="removeDrug('\${item}')">Del</button>
                    </td>
                </tr>
            \`).join('');
            document.getElementById('drugList').innerHTML = masterList.map(m => \`<option value="\${m}">\`).join('');
        }
    }

    async function registerDrug() {
        const i = document.getElementById('newDrugName');
        const name = i.value.trim().toUpperCase();
        if (!name) return;
        const res = await fetch('/api/master-drugs', {
            method: 'POST',
            headers: {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'},
            body: JSON.stringify({ drug_name: name })
        });
        if(res.ok) { i.value = ''; loadMasterDrugs(); }
    }

    async function removeDrug(name) {
        if(confirm("Delete drug from master directory?")) {
            await fetch('/api/master-drugs/' + encodeURIComponent(name), { method: 'DELETE', headers: {'Authorization': 'Bearer ' + token} });
            loadMasterDrugs();
        }
    }

    // DISPENSE & AUTO SYNC
    function setQty(v) { 
        document.getElementById('dispenseAmount').value = v; 
        document.getElementById('recordBtn').focus(); 
    }

    async function dispenseDrug() {
        const nI = document.getElementById('searchDrug'), aI = document.getElementById('dispenseAmount');
        const name = nI.value.trim().toUpperCase(), qty = parseInt(aI.value);
        if (!name || isNaN(qty) || qty <= 0) return alert("Select drug and valid quantity");

        const res = await fetch('/api/dispense', {
            method: 'POST',
            headers: {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'},
            body: JSON.stringify({ drug_name: name, qty: qty })
        });

        if(res.ok) {
            nI.value = ''; aI.value = '';
            nI.focus();
            syncData();
        }
    }

    async function syncData() {
        if(!token) return;

        let url = '/api/dispense/sync';
        if(role === 'ADMIN') {
            const selectedFilter = document.getElementById('filterZoneSelect').value;
            url += '?zone=' + selectedFilter;
        }

        const res = await fetch(url, { headers: {'Authorization': 'Bearer ' + token} });
        const data = await res.json();

        if(res.status === 403 && data.error === 'ACCOUNT_DISABLED') {
            alert("Your account has been disabled by the Administrator.");
            logout();
            return;
        }

        if(res.ok) {
            liveDispenseLog = data;
            
            // Calculate Daily Totals
            dailyTotals = {};
            liveDispenseLog.forEach(i => {
                dailyTotals[i.drug_name] = (dailyTotals[i.drug_name] || 0) + i.qty;
            });

            // Render Totals
            document.getElementById('dailyBody').innerHTML = Object.keys(dailyTotals).sort().map(k => \`
                <tr><td><b>\${k}</b></td><td><span class="badge">\${dailyTotals[k]}</span></td></tr>
            \`).join('');

            // Render Live Feed
            document.getElementById('historyBody').innerHTML = liveDispenseLog.map(i => \`
                <tr>
                    <td><small style="color:var(--text-muted)">\${new Date(i.timestamp).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'})}</small></td>
                    <td><b>\${i.drug_name}</b> (\${i.qty})<br><small style="color:var(--accent)">\${i.zone}</small></td>
                    <td><small>\${i.entered_by}</small></td>
                    <td><button class="action-btn" style="background:var(--danger); color:white;" onclick="deleteEntry(\${i.id})">X</button></td>
                </tr>
            \`).join('');
        }
    }

    async function deleteEntry(id) {
        if(confirm("Remove this entry?")) {
            await fetch('/api/dispense/' + id, { method: 'DELETE', headers: {'Authorization': 'Bearer ' + token} });
            syncData();
        }
    }

    // ADMIN CONTROLS & AUDIT LOGS
    async function loadAdminData() {
        if(role !== 'ADMIN') return;

        // User list with entry counts
        const resU = await fetch('/api/users', { headers: {'Authorization': 'Bearer ' + token} });
        const users = await resU.json();
        if(resU.ok) {
            document.getElementById('adminUserList').innerHTML = users.map(u => \`
                <tr>
                    <td><b>\${u.username}</b><br><small style="color:var(--text-muted)">\${u.zone}</small></td>
                    <td><span class="badge">\${u.total_entries}</span></td>
                    <td><span class="badge \${u.status ? 'badge-on':'badge-off'}">\${u.status ? 'ON':'OFF'}</span></td>
                    <td>
                        \${u.username !== 'admin' ? \`
                            <button class="action-btn \${u.status ? '':'badge-on'}" style="background:\${u.status ? 'var(--danger)':'var(--success)'}; color:white;" onclick="toggleUser(\${u.id}, \${u.status ? 0 : 1})">\${u.status ? 'OFF':'ON'}</button>
                        \` : ''}
                    </td>
                </tr>
            \`).join('');

            // Filter zones dropdown
            const zones = [...new Set(users.map(u => u.zone))].filter(z => z !== 'ALL');
            const filterSelect = document.getElementById('filterZoneSelect');
            filterSelect.innerHTML = '<option value="ALL">All Zones</option>' + zones.map(z => \`<option value="\${z}">\${z}</option>\`).join('');
        }

        // Login/Logout Audit Logs
        const resA = await fetch('/api/admin/audit-logs', { headers: {'Authorization': 'Bearer ' + token} });
        const audit = await resA.json();
        if(resA.ok) {
            document.getElementById('auditLogBody').innerHTML = audit.map(a => \`
                <tr>
                    <td><small style="color:var(--text-muted)">\${new Date(a.timestamp).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'})}</small></td>
                    <td><b>\${a.username}</b></td>
                    <td><span class="badge \${a.action === 'LOGIN' ? 'badge-on':'badge-off'}">\${a.action}</span></td>
                </tr>
            \`).join('');
        }
    }

    async function createUser() {
        const u = document.getElementById('newU').value, p = document.getElementById('newP').value, z = document.getElementById('newZ').value, r = document.getElementById('newR').value;
        if(!u || !p || !z) return alert("Fill in username, password, and zone");
        await fetch('/api/users', { method: 'POST', headers: {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}, body: JSON.stringify({username: u, password: p, zone: z, role: r}) });
        document.getElementById('newU').value = ''; document.getElementById('newP').value = ''; document.getElementById('newZ').value = '';
        loadAdminData();
    }

    async function toggleUser(id, status) {
        await fetch('/api/users/' + id + '/status', { method: 'PUT', headers: {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}, body: JSON.stringify({status}) });
        loadAdminData();
    }

    // PDF REPORTING
    function generateReport() {
        const r = document.getElementById('pdfRemarks').value.trim();
        if (!r) return alert("Remarks Required");
        const { jsPDF } = window.jspdf; 
        const doc = new jsPDF();
        
        doc.setFontSize(16);
        doc.text("PHARMA-SYNC PRO DAILY REPORT", 14, 20);
        doc.setFontSize(10); 
        doc.text("Generated: " + new Date().toLocaleString() + " | Zone: " + zone + " | Remarks: " + r, 14, 28);
        
        doc.autoTable({ 
            startY: 35, 
            head: [['Drug Name', 'Total Dispense Quantity']], 
            body: Object.keys(dailyTotals).sort().map(k => [k, dailyTotals[k]]),
            didDrawPage: function (data) {
                if (doc.internal.getNumberOfPages() === 1) {
                    doc.setFontSize(8);
                    doc.text("System Architect: Debanjan Singha", 14, doc.internal.pageSize.height - 10);
                }
            }
        });
        
        doc.save("PharmaReport_" + Date.now() + ".pdf");
    }

    function exportBackup() {
        const blob = new Blob([JSON.stringify({ master: masterList, dispenses: liveDispenseLog })], {type: 'application/json'});
        const a = document.createElement('a'); 
        a.href = URL.createObjectURL(blob); 
        a.download = "PharmaBackup_" + Date.now() + ".json"; 
        a.click();
    }

    function filterTable(id, val) {
        const rows = document.getElementById(id).rows; 
        const s = val.toUpperCase();
        for (let r of rows) r.style.display = r.innerText.toUpperCase().includes(s) ? "" : "none";
    }

    // INITIALIZATION
    if(token) {
        document.getElementById('loginOverlay').style.display = 'none';
        document.getElementById('uName').innerText = user;
        document.getElementById('zoneBadge').innerText = zone;

        if(role === 'ADMIN') {
            document.getElementById('adminPanel').style.display = 'block';
            document.getElementById('filterZoneSelect').style.display = 'inline-block';
            loadAdminData();
        }

        loadMasterDrugs();
        syncData();
        setInterval(() => {
            syncData();
            if(role === 'ADMIN') loadAdminData();
        }, 3000); // 3-second live sync interval
    }
</script>
</body>
</html>
    `);
});

app.listen(PORT, () => console.log(`Pharma-Sync Pro running on port ${PORT}`));
