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

    // 2. Zone-Specific Master Drugs Directory
    db.run(`CREATE TABLE IF NOT EXISTS master_drugs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        zone TEXT,
        drug_name TEXT,
        UNIQUE(zone, drug_name)
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
    if (!username || !password) return res.status(400).json({ error: "Username and password required" });

    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: "User not found" });
        if (user.status !== 1) return res.status(403).json({ error: "Account is turned OFF by Admin." });

        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) return res.status(400).json({ error: "Invalid Password" });

        db.run("INSERT INTO audit_logs (username, zone, action) VALUES (?, ?, 'LOGIN')", [user.username, user.zone]);

        const token = jwt.sign({ id: user.id, username: user.username, role: user.role, zone: user.zone }, SECRET_KEY, { expiresIn: '24h' });
        res.json({ token, role: user.role, username: user.username, zone: user.zone });
    });
});

app.post('/api/logout', authenticateToken, (req, res) => {
    db.run("INSERT INTO audit_logs (username, zone, action) VALUES (?, ?, 'LOGOUT')", [req.user.username, req.user.zone]);
    res.json({ message: "Logged out successfully" });
});

// --- MASTER DRUG DIRECTORY ROUTES (ZONE SPECIFIC) ---

app.get('/api/master-drugs', authenticateToken, (req, res) => {
    const targetZone = (req.user.role === 'ADMIN' && req.query.zone) ? req.query.zone : req.user.zone;
    
    let query = "SELECT drug_name FROM master_drugs WHERE zone = ? ORDER BY drug_name ASC";
    let params = [targetZone];

    if (req.user.role === 'ADMIN' && targetZone === 'ALL') {
        query = "SELECT DISTINCT drug_name FROM master_drugs ORDER BY drug_name ASC";
        params = [];
    }

    db.all(query, params, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows.map(r => r.drug_name));
    });
});

app.post('/api/master-drugs', authenticateToken, (req, res) => {
    if (!req.body.drug_name) return res.status(400).json({ error: "Drug name required" });
    const name = req.body.drug_name.trim().toUpperCase();
    const targetZone = (req.user.role === 'ADMIN' && req.body.zone) ? req.body.zone : req.user.zone;

    db.run("INSERT OR IGNORE INTO master_drugs (zone, drug_name) VALUES (?, ?)", [targetZone, name], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Drug registered successfully" });
    });
});

app.delete('/api/master-drugs/:name', authenticateToken, (req, res) => {
    const targetZone = (req.user.role === 'ADMIN' && req.query.zone) ? req.query.zone : req.user.zone;
    db.run("DELETE FROM master_drugs WHERE drug_name = ? AND zone = ?", [req.params.name, targetZone], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Drug deleted from zone directory" });
    });
});

// ADMIN BULK IMPORT FOR MASTER DIRECTORY
app.post('/api/master-drugs/import', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required for import" });

    const { mode, drugs, zone } = req.body; // mode: 'reset' or 'merge'
    const targetZone = zone || 'MAIN-STORE';

    if (!Array.isArray(drugs) || drugs.length === 0) {
        return res.status(400).json({ error: "No drug list provided" });
    }

    db.serialize(() => {
        if (mode === 'reset') {
            db.run("DELETE FROM master_drugs WHERE zone = ?", [targetZone]);
        }

        const stmt = db.prepare("INSERT OR IGNORE INTO master_drugs (zone, drug_name) VALUES (?, ?)");
        drugs.forEach(d => {
            if (typeof d === 'string' && d.trim().length > 0) {
                stmt.run(targetZone, d.trim().toUpperCase());
            }
        });
        stmt.finalize((err) => {
            if (err) return res.status(500).json({ error: "Import failed" });
            res.json({ message: `Successfully ${mode === 'reset' ? 'reset and imported' : 'merged'} ${drugs.length} drugs into ${targetZone}.` });
        });
    });
});

// --- DISPENSE & AUTO-SYNC ROUTES ---

app.post('/api/dispense', authenticateToken, (req, res) => {
    const { drug_name, qty } = req.body;
    if (!drug_name || !qty) return res.status(400).json({ error: "Drug and quantity required" });

    const drugName = drug_name.trim().toUpperCase();
    const zone = req.user.role === 'ADMIN' ? (req.body.zone || 'MAIN-STORE') : req.user.zone;

    db.run("INSERT INTO dispenses (zone, drug_name, qty, entered_by) VALUES (?, ?, ?, ?)", 
        [zone, drugName, parseInt(qty), req.user.username], 
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: "Entry recorded" });
        }
    );
});

app.get('/api/dispense/sync', authenticateToken, (req, res) => {
    let query = "SELECT * FROM dispenses WHERE zone = ? ORDER BY id DESC LIMIT 150";
    let params = [req.user.zone];

    if (req.user.role === 'ADMIN') {
        const filterZone = req.query.zone;
        if (filterZone && filterZone !== 'ALL') {
            query = "SELECT * FROM dispenses WHERE zone = ? ORDER BY id DESC LIMIT 150";
            params = [filterZone];
        } else {
            query = "SELECT * FROM dispenses ORDER BY id DESC LIMIT 250";
            params = [];
        }
    }

    db.all(query, params, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// UNDO LAST DISPENSE ENTRY (ZONE SPECIFIC)
app.post('/api/dispense/undo', authenticateToken, (req, res) => {
    const targetZone = req.user.role === 'ADMIN' ? (req.body.zone || req.user.zone) : req.user.zone;
    
    db.get("SELECT id FROM dispenses WHERE zone = ? ORDER BY id DESC LIMIT 1", [targetZone], (err, row) => {
        if (err || !row) return res.status(404).json({ error: "No recent entries found to undo." });

        db.run("DELETE FROM dispenses WHERE id = ?", [row.id], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: "Last entry undone successfully." });
        });
    });
});

// RESET TOTALS & HISTORY (ZONE SPECIFIC)
app.post('/api/dispense/reset-zone', authenticateToken, (req, res) => {
    const targetZone = req.user.role === 'ADMIN' ? (req.body.zone || req.user.zone) : req.user.zone;

    db.run("DELETE FROM dispenses WHERE zone = ?", [targetZone], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: `All totals and history reset for zone: ${targetZone}` });
    });
});

app.delete('/api/dispense/:id', authenticateToken, (req, res) => {
    db.run("DELETE FROM dispenses WHERE id = ?", [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Record deleted" });
    });
});

// --- ADMIN AUDIT & USER CONTROL ROUTES ---

app.get('/api/users', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required" });
    
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
    if (!username || !password || !zone) {
        return res.status(400).json({ error: "Username, password, and zone are required" });
    }

    try {
        const hash = await bcrypt.hash(password, 10);
        const formattedZone = zone.trim().toUpperCase();

        db.run("INSERT INTO users (username, password, role, zone, status) VALUES (?, ?, ?, ?, 1)", 
            [username.trim(), hash, role || 'OPERATOR', formattedZone], 
            function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE')) return res.status(400).json({ error: "Username already exists." });
                    return res.status(500).json({ error: err.message });
                }
                res.json({ message: "User created successfully!" });
            }
        );
    } catch (e) {
        res.status(500).json({ error: "Password encryption error" });
    }
});

app.put('/api/users/:id/status', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required" });
    db.run("UPDATE users SET status = ? WHERE id = ?", [req.body.status, req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Status updated" });
    });
});

app.get('/api/admin/audit-logs', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required" });
    db.all("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 50", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// --- FRONTEND APP INTERFACE (BRIGHT VIBRANT LIGHT THEME) ---

app.get('/', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHARMA-SYNC PRO | VIBRANT CLINICAL CONSOLE</title>
    <meta name="author" content="Debanjan Singha">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.23/jspdf.plugin.autotable.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #f0f4f9;
            --card-bg: #ffffff;
            --card-inner: #f8fafc;
            --primary: #0284c7;
            --primary-hover: #0369a1;
            --secondary: #6366f1;
            --accent: #06b6d4;
            --success: #10b981;
            --success-hover: #059669;
            --danger: #ef4444;
            --danger-hover: #dc2626;
            --warning: #f59e0b;
            --text-main: #0f172a;
            --text-muted: #64748b;
            --border: #cbd5e1;
            --shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.05), 0 8px 10px -6px rgba(0, 0, 0, 0.01);
        }

        body { font-family: 'Plus Jakarta Sans', sans-serif; background-color: var(--bg); color: var(--text-main); margin: 0; padding: 20px; }
        .container { max-width: 1550px; margin: auto; }

        .app-grid { display: grid; grid-template-columns: 360px 1fr 400px; gap: 20px; align-items: start; }
        @media (max-width: 1300px) { .app-grid { grid-template-columns: 1fr 1fr; } }
        @media (max-width: 850px) { .app-grid { grid-template-columns: 1fr; } }

        .header-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; background: linear-gradient(135deg, #ffffff 0%, #e0f2fe 100%); padding: 18px 28px; border-radius: 16px; border: 2px solid #bae6fd; box-shadow: var(--shadow); }
        .panel { background: var(--card-bg); padding: 22px; border-radius: 16px; border: 1px solid #e2e8f0; margin-bottom: 20px; box-shadow: var(--shadow); }
        .panel h2 { font-size: 15px; font-weight: 800; margin-top: 0; margin-bottom: 16px; color: var(--primary); border-bottom: 2px solid #f1f5f9; padding-bottom: 10px; text-transform: uppercase; letter-spacing: 0.6px; display: flex; justify-content: space-between; align-items: center; }

        input, select, textarea { width: 100%; padding: 11px 14px; border: 2px solid #e2e8f0; border-radius: 10px; font-size: 13px; font-weight: 600; box-sizing: border-box; margin-bottom: 10px; background: var(--card-inner); color: var(--text-main); transition: 0.2s; }
        input:focus, select:focus { outline: none; border-color: var(--primary); background: #ffffff; box-shadow: 0 0 0 3px rgba(2, 132, 199, 0.15); }
        
        .primary-btn { background: var(--primary); color: white; padding: 11px; border: none; border-radius: 10px; cursor: pointer; font-weight: 700; width: 100%; transition: 0.2s; font-size: 13px; letter-spacing: 0.3px; box-shadow: 0 4px 12px rgba(2, 132, 199, 0.25); }
        .primary-btn:hover { background: var(--primary-hover); transform: translateY(-1px); }

        .qty-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin-bottom: 12px; }
        .qty-pill { background: #f1f5f9; border: 2px solid #cbd5e1; color: var(--text-main); padding: 10px; border-radius: 8px; cursor: pointer; font-size: 13px; font-weight: 800; transition: 0.15s; }
        .qty-pill:hover { background: var(--primary); color: white; border-color: var(--primary); }

        .table-wrap { max-height: 380px; overflow-y: auto; border: 2px solid #e2e8f0; border-radius: 10px; background: #ffffff; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th { background: #f8fafc; padding: 12px; text-align: left; color: var(--text-muted); font-weight: 700; position: sticky; top: 0; z-index: 10; border-bottom: 2px solid #e2e8f0; text-transform: uppercase; font-size: 11px; }
        td { padding: 10px 12px; border-bottom: 1px solid #f1f5f9; font-weight: 500; }

        .badge { background: #e0f2fe; color: #0284c7; padding: 4px 8px; border-radius: 6px; font-weight: 800; font-size: 11px; }
        .badge-on { background: #dcfce7; color: #15803d; }
        .badge-off { background: #ffe4e6; color: #be123c; }
        .action-btn { cursor: pointer; font-size: 11px; font-weight: 700; border: none; padding: 5px 10px; border-radius: 6px; transition: 0.2s; }
        
        #loginOverlay { position: fixed; inset: 0; background: linear-gradient(135deg, #0284c7 0%, #4f46e5 100%); display: grid; place-items: center; z-index: 2000; }
        .login-box { width: 340px; background: #ffffff; padding: 35px; border-radius: 20px; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25); border: 1px solid #ffffff; }

        .modal-overlay { position: fixed; inset: 0; background: rgba(15, 23, 42, 0.6); display: none; place-items: center; z-index: 3000; backdrop-filter: blur(4px); }
        .modal-box { width: 440px; background: #ffffff; padding: 25px; border-radius: 16px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.2); }

        .panel-credit { margin-top: 20px; padding-top: 12px; border-top: 2px dashed #e2e8f0; font-size: 11px; color: var(--text-muted); text-align: center; font-weight: 600; }
        .sync-dot { display: inline-block; width: 10px; height: 10px; background: var(--success); border-radius: 50%; margin-right: 6px; box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.2); }
    </style>
</head>
<body>

<!-- LOGIN MODAL -->
<div id="loginOverlay">
    <div class="login-box">
        <h2 style="text-align:center; color:var(--primary); margin-top:0; font-size:24px; font-weight:800;">PHARMA<span style="color:#4f46e5">SYNC</span></h2>
        <p style="text-align:center; color:var(--text-muted); font-size:12px; margin-top:-10px; margin-bottom:20px; font-weight:600;">Multi-Zone Pharmacy Management</p>
        <input type="text" id="loginUser" placeholder="Username">
        <input type="password" id="loginPass" placeholder="Password">
        <button class="primary-btn" style="height:45px; font-size:14px;" onclick="login()">LOG IN</button>
        <p id="errMsg" style="color:var(--danger); font-size:12px; text-align:center; margin-top:12px; margin-bottom:0; font-weight:700;"></p>
    </div>
</div>

<!-- IMPORT MODAL (ADMIN ONLY) -->
<div id="importModal" class="modal-overlay">
    <div class="modal-box">
        <h2 style="margin-top:0; color:var(--primary); font-size:16px;">📥 Bulk Import Master Directory</h2>
        <p style="font-size:12px; color:var(--text-muted); margin-bottom:10px;">Paste drug names below (separated by commas or newlines):</p>
        <textarea id="importRawText" rows="6" placeholder="PARACETAMOL 500MG&#10;AMOXICILLIN 250MG&#10;IBUPROFEN 400MG"></textarea>
        
        <div style="display:flex; gap:8px; margin-top:15px;">
            <button class="primary-btn" style="background:var(--danger);" onclick="executeImport('reset')">Reset & Add</button>
            <button class="primary-btn" style="background:var(--success);" onclick="executeImport('merge')">Merge & Add</button>
            <button class="primary-btn" style="background:#64748b;" onclick="closeImportModal()">Cancel</button>
        </div>
    </div>
</div>

<div class="container">
    <!-- TOP HEADER -->
    <div class="header-bar">
        <div>
            <h1 style="margin:0; font-size:22px; color:var(--text-main); font-weight:800; display:inline-block;">PHARMA<span style="color:var(--primary)">SYNC</span> PRO</h1>
            <span id="zoneBadge" class="badge" style="margin-left:12px; font-size:12px; background:#e0f2fe; color:#0284c7;">ZONE</span>
        </div>
        <div style="display:flex; align-items:center; gap:12px;">
            <span style="font-size:13px; color:var(--text-muted); font-weight:700;"><span class="sync-dot"></span>LIVE AUTO-SYNC</span>
            <span id="uName" style="font-weight:800; color:var(--primary); background:#ffffff; padding:6px 14px; border-radius:8px; border:1px solid #bae6fd;"></span>
            <button onclick="exportBackup()" style="background:var(--secondary); color:white; border:none; padding:10px 14px; border-radius:8px; cursor:pointer; font-weight:700; font-size:12px;">💾 BACKUP</button>
            <button onclick="logout()" style="background:var(--danger); color:white; border:none; padding:10px 14px; border-radius:8px; cursor:pointer; font-weight:700; font-size:12px;">LOGOUT</button>
        </div>
    </div>

    <div class="app-grid">
        <!-- LEFT COLUMN: MASTER DIRECTORY & ADMIN USER MONITOR -->
        <div>
            <!-- ADMIN ACCESS CONTROL (VISIBLE TO ADMIN ONLY) -->
            <div id="adminPanel" class="panel" style="display:none; border:2px solid #c7d2fe;">
                <h2>👑 Admin Access & Users</h2>
                <input type="text" id="newU" placeholder="New Username">
                <input type="password" id="newP" placeholder="New Password">
                <input type="text" id="newZ" placeholder="Assign Zone (e.g., ER-WARD)">
                <select id="newR"><option value="OPERATOR">OPERATOR</option><option value="ADMIN">ADMIN</option></select>
                <button class="primary-btn" style="background:var(--success); color:white; margin-bottom:15px;" onclick="createUser()">CREATE USER</button>

                <h3 style="font-size:12px; color:var(--text-muted); margin-bottom:6px; font-weight:800;">User Activity Stats</h3>
                <div class="table-wrap" style="max-height: 160px;">
                    <table>
                        <thead><tr><th>User/Zone</th><th>Entries</th><th>Status</th><th>Action</th></tr></thead>
                        <tbody id="adminUserList"></tbody>
                    </table>
                </div>

                <h3 style="font-size:12px; color:var(--text-muted); margin-top:15px; margin-bottom:6px; font-weight:800;">Login/Logout Audit Log</h3>
                <div class="table-wrap" style="max-height: 140px;">
                    <table>
                        <thead><tr><th>Time</th><th>User</th><th>Action</th></tr></thead>
                        <tbody id="auditLogBody"></tbody>
                    </table>
                </div>
            </div>

            <!-- MASTER DRUG DIRECTORY (ZONE SPECIFIC) -->
            <div class="panel">
                <h2>
                    <span>📦 Zone Master Directory</span>
                    <button id="importBtn" style="display:none; background:#4f46e5; color:white; border:none; padding:4px 8px; border-radius:6px; font-size:11px; font-weight:700; cursor:pointer;" onclick="openImportModal()">📥 Import</button>
                </h2>
                <input type="text" id="newDrugName" placeholder="New drug name..." onkeydown="if(event.key==='Enter') registerDrug()">
                <button class="primary-btn" style="background:#0284c7;" onclick="registerDrug()">REGISTER DRUG</button>
                
                <input type="text" style="margin-top:15px" onkeyup="filterTable('masterBody', this.value)" placeholder="Search zone directory...">
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
            <div style="display: grid; grid-template-columns: 1fr 110px; gap: 10px;">
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
            <button class="primary-btn" style="background:var(--success); color:white; height:45px; font-size:15px;" id="recordBtn" onclick="dispenseDrug()">RECORD ENTRY</button>

            <!-- ZONE SPECIFIC ACTION CONTROLS: UNDO AND RESET TOTALS -->
            <div style="display:flex; gap:10px; margin-top:15px;">
                <button class="primary-btn" style="background:#f59e0b; color:white; font-size:12px;" onclick="undoLastEntry()">↩️ UNDO LAST ENTRY</button>
                <button class="primary-btn" style="background:#ef4444; color:white; font-size:12px;" onclick="resetZoneTotals()">🚨 RESET TOTALS & HISTORY</button>
            </div>

            <h2 style="margin-top:25px;">📊 Today's Cumulative Totals</h2>
            <input type="text" onkeyup="filterTable('dailyBody', this.value)" placeholder="Filter totals...">
            <div class="table-wrap" style="max-height: 260px;">
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
                    <select id="filterZoneSelect" onchange="syncData()" style="width:auto; margin-bottom:0; padding:2px 8px; font-size:11px; display:none;">
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
                <button class="primary-btn" style="background:var(--danger); color:white; height:42px;" onclick="generateReport()">GENERATE PDF REPORT</button>
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
        const u = document.getElementById('loginUser').value.trim(), p = document.getElementById('loginPass').value.trim();
        const res = await fetch('/api/login', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({username: u, password: p}) });
        const d = await res.json();
        if(res.ok) {
            localStorage.setItem('p_token', d.token); 
            localStorage.setItem('p_role', d.role); 
            localStorage.setItem('p_user', d.username); 
            localStorage.setItem('p_zone', d.zone);
            location.reload();
        } else { 
            document.getElementById('errMsg').innerText = d.error || "Login failed"; 
        }
    }

    async function logout() { 
        if(token) {
            await fetch('/api/logout', { method: 'POST', headers: {'Authorization': 'Bearer ' + token} });
        }
        localStorage.clear(); 
        location.reload(); 
    }

    // MASTER DIRECTORY MANAGEMENT (ZONE SPECIFIC)
    async function loadMasterDrugs() {
        const selectedZone = (role === 'ADMIN' && document.getElementById('filterZoneSelect')) ? document.getElementById('filterZoneSelect').value : zone;
        const res = await fetch('/api/master-drugs?zone=' + encodeURIComponent(selectedZone), { headers: {'Authorization': 'Bearer ' + token} });
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
        if (!name) return alert("Enter a valid drug name.");
        
        const selectedZone = (role === 'ADMIN' && document.getElementById('filterZoneSelect')) ? document.getElementById('filterZoneSelect').value : zone;

        const res = await fetch('/api/master-drugs', {
            method: 'POST',
            headers: {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'},
            body: JSON.stringify({ drug_name: name, zone: selectedZone })
        });
        if(res.ok) { i.value = ''; loadMasterDrugs(); }
    }

    async function removeDrug(name) {
        if(confirm("Delete drug from this zone's master directory?")) {
            const selectedZone = (role === 'ADMIN' && document.getElementById('filterZoneSelect')) ? document.getElementById('filterZoneSelect').value : zone;
            await fetch('/api/master-drugs/' + encodeURIComponent(name) + '?zone=' + encodeURIComponent(selectedZone), { method: 'DELETE', headers: {'Authorization': 'Bearer ' + token} });
            loadMasterDrugs();
        }
    }

    // ADMIN BULK IMPORT MODAL FUNCTIONS
    function openImportModal() { document.getElementById('importModal').style.display = 'grid'; }
    function closeImportModal() { document.getElementById('importModal').style.display = 'none'; }

    async function executeImport(mode) {
        const raw = document.getElementById('importRawText').value;
        const drugsArr = raw.split(/[,\\n]/).map(d => d.trim()).filter(d => d.length > 0);
        
        if(drugsArr.length === 0) return alert("Please paste drug names first.");

        const selectedZone = document.getElementById('filterZoneSelect') ? document.getElementById('filterZoneSelect').value : zone;

        const res = await fetch('/api/master-drugs/import', {
            method: 'POST',
            headers: {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'},
            body: JSON.stringify({ mode: mode, drugs: drugsArr, zone: selectedZone })
        });

        const d = await res.json();
        if(res.ok) {
            alert(d.message);
            document.getElementById('importRawText').value = '';
            closeImportModal();
            loadMasterDrugs();
        } else {
            alert(d.error || "Import failed");
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
            body: JSON.stringify({ drug_name: name, qty: qty, zone: (role === 'ADMIN' ? document.getElementById('filterZoneSelect').value : zone) })
        });

        if(res.ok) {
            nI.value = ''; aI.value = '';
            nI.focus();
            syncData();
        }
    }

    // UNDO & RESET ACTIONS WITH MANDATORY CONFIRMATION
    async function undoLastEntry() {
        if (!confirm("⚠️ CONFIRMATION: Are you sure you want to UNDO the last dispense entry for your zone?")) return;

        const res = await fetch('/api/dispense/undo', {
            method: 'POST',
            headers: {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'},
            body: JSON.stringify({ zone: (role === 'ADMIN' ? document.getElementById('filterZoneSelect').value : zone) })
        });

        const d = await res.json();
        if (res.ok) {
            alert(d.message);
            syncData();
        } else {
            alert(d.error || "Could not undo entry.");
        }
    }

    async function resetZoneTotals() {
        if (!confirm("🚨 WARNING: This action will PERMANENTLY ERASE all totals and history for this zone! Proceed?")) return;

        const res = await fetch('/api/dispense/reset-zone', {
            method: 'POST',
            headers: {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'},
            body: JSON.stringify({ zone: (role === 'ADMIN' ? document.getElementById('filterZoneSelect').value : zone) })
        });

        const d = await res.json();
        if (res.ok) {
            alert(d.message);
            syncData();
        } else {
            alert(d.error || "Reset failed.");
        }
    }

    async function syncData() {
        if(!token) return;

        let url = '/api/dispense/sync';
        if(role === 'ADMIN' && document.getElementById('filterZoneSelect')) {
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
                    <td><small style="color:var(--text-muted); font-weight:700;">\${new Date(i.timestamp).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'})}</small></td>
                    <td><b>\${i.drug_name}</b> (\${i.qty})<br><small style="color:var(--primary); font-weight:800;">\${i.zone}</small></td>
                    <td><small>\${i.entered_by}</small></td>
                    <td><button class="action-btn" style="background:var(--danger); color:white;" onclick="deleteEntry(\${i.id})">X</button></td>
                </tr>
            \`).join('');
        }
    }

    async function deleteEntry(id) {
        if(confirm("Remove this individual entry?")) {
            await fetch('/api/dispense/' + id, { method: 'DELETE', headers: {'Authorization': 'Bearer ' + token} });
            syncData();
        }
    }

    // ADMIN CONTROLS & AUDIT LOGS
    async function loadAdminData() {
        if(role !== 'ADMIN') return;

        const resU = await fetch('/api/users', { headers: {'Authorization': 'Bearer ' + token} });
        const users = await resU.json();
        if(resU.ok) {
            document.getElementById('adminUserList').innerHTML = users.map(u => \`
                <tr>
                    <td><b>\${u.username}</b><br><small style="color:var(--text-muted); font-weight:700;">\${u.zone}</small></td>
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
            const currentSelected = filterSelect.value;
            filterSelect.innerHTML = '<option value="ALL">All Zones</option>' + zones.map(z => \`<option value="\${z}">\${z}</option>\`).join('');
            if(currentSelected) filterSelect.value = currentSelected;
        }

        const resA = await fetch('/api/admin/audit-logs', { headers: {'Authorization': 'Bearer ' + token} });
        const audit = await resA.json();
        if(resA.ok) {
            document.getElementById('auditLogBody').innerHTML = audit.map(a => \`
                <tr>
                    <td><small style="color:var(--text-muted); font-weight:700;">\${new Date(a.timestamp).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'})}</small></td>
                    <td><b>\${a.username}</b></td>
                    <td><span class="badge \${a.action === 'LOGIN' ? 'badge-on':'badge-off'}">\${a.action}</span></td>
                </tr>
            \`).join('');
        }
    }

    async function createUser() {
        const u = document.getElementById('newU').value.trim(), 
              p = document.getElementById('newP').value.trim(), 
              z = document.getElementById('newZ').value.trim(), 
              r = document.getElementById('newR').value;

        if(!u || !p || !z) return alert("Fill in username, password, and zone");

        const res = await fetch('/api/users', { 
            method: 'POST', 
            headers: {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}, 
            body: JSON.stringify({username: u, password: p, zone: z, role: r}) 
        });
        
        const d = await res.json();
        if(res.ok) {
            alert("User Created Successfully!");
            document.getElementById('newU').value = ''; 
            document.getElementById('newP').value = ''; 
            document.getElementById('newZ').value = '';
            loadAdminData();
        } else {
            alert(d.error || "User creation failed");
        }
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
            document.getElementById('importBtn').style.display = 'inline-block';
            document.getElementById('filterZoneSelect').style.display = 'inline-block';
            loadAdminData();
        }

        loadMasterDrugs();
        syncData();
        setInterval(() => {
            syncData();
            if(role === 'ADMIN') loadAdminData();
        }, 3000); // 3-second auto-sync loop
    }
</script>
</body>
</html>
    `);
});

app.listen(PORT, () => console.log(`Pharma-Sync Pro running on port ${PORT}`));
