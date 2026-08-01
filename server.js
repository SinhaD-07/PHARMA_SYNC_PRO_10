const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Excel parsing library dependency fallback check (Included via client script for browser parsing, or backend processing)
let xlsx;
try {
    xlsx = require('xlsx');
} catch (e) {
    console.log("Note: Install 'xlsx' package (`npm install xlsx`) for backend binary excel processing.");
}

const app = express();
const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.JWT_SECRET || "pharma_sync_ultra_secure_debanjan_2026_key";

// Legal Copyright Notice Verification
const COPYRIGHT_OWNER = "Debanjan Singha";
console.log(`================================================================`);
console.log(` PHARMA-SYNC PRO | ALL RIGHTS RESERVED`);
console.log(` Proprietary Software Architecture Created by ${COPYRIGHT_OWNER}`);
console.log(` Unauthorized distribution, cloning, or usage is strictly prohibited.`);
console.log(`================================================================`);

app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Database Initialization
const db = new sqlite3.Database('./pharmacy.db', (err) => {
    if (!err) {
        console.log("Database initialized successfully.");
        initDb();
    }
});

function initDb() {
    // 1. Users table (Stores phone number & multi-zone JSON array)
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        phone TEXT,
        password TEXT,
        role TEXT,           -- 'ADMIN' or 'OPERATOR'
        zones TEXT,          -- Stored as JSON string array e.g. ["NORTH", "SOUTH"]
        status INTEGER DEFAULT 1
    )`);

    // 2. Master Drugs Directory
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

    // 4. Audit Logs
    db.run(`CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        phone TEXT,
        zone TEXT,
        action TEXT, -- 'LOGIN', 'LOGOUT', etc.
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Default Master Admin Setup
    db.get("SELECT * FROM users WHERE role = 'ADMIN'", async (err, row) => {
        if (!row) {
            const hash = await bcrypt.hash('admin123', 10);
            db.run(
                "INSERT INTO users (username, phone, password, role, zones, status) VALUES ('admin', '0000000000', ?, 'ADMIN', '[\"ALL\"]', 1)",
                [hash]
            );
            console.log("Master Admin initialized: admin / admin123");
        }
    });
}

// Security Middleware (Strict 8-hour Token Expiry Enforcement)
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Access Denied. Please Log In." });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(403).json({ error: "Session expired or invalid. Please login again." });

        db.get("SELECT * FROM users WHERE id = ?", [decoded.id], (err, user) => {
            if (err || !user) return res.status(404).json({ error: "User profile not found." });
            
            // Explicit Blocked User Guardrail
            if (user.status !== 1) {
                return res.status(403).json({ 
                    error: "ACCESS_DISABLED", 
                    message: "ERROR! PLEASE CONTACT TO THE ADMIN" 
                });
            }
            req.user = user;
            next();
        });
    });
};

// --- AUTHENTICATION & ADMIN PROFILE ROUTES ---

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Username and password required" });

    db.get("SELECT * FROM users WHERE username = ? OR phone = ?", [username, username], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: "Invalid credentials" });
        
        if (user.status !== 1) {
            return res.status(403).json({ error: "ERROR! PLEASE CONTACT TO THE ADMIN" });
        }

        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) return res.status(400).json({ error: "Invalid credentials" });

        // Log audit
        db.run("INSERT INTO audit_logs (username, phone, zone, action) VALUES (?, ?, ?, 'LOGIN')", 
            [user.username, user.phone, user.zones]);

        // Token generated with strict 8 Hours lifespan
        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role }, 
            SECRET_KEY, 
            { expiresIn: '8h' }
        );

        let userZones = [];
        try { userZones = JSON.parse(user.zones); } catch(e) { userZones = [user.zones]; }

        res.json({ 
            token, 
            role: user.role, 
            username: user.username, 
            phone: user.phone,
            zones: userZones 
        });
    });
});

app.post('/api/logout', authenticateToken, (req, res) => {
    const activeZone = req.body.zone || "N/A";
    db.run("INSERT INTO audit_logs (username, phone, zone, action) VALUES (?, ?, ?, 'LOGOUT')", 
        [req.user.username, req.user.phone, activeZone]);
    res.json({ message: "Logged out successfully" });
});

// Admin can change their own username and password
app.put('/api/admin/profile', authenticateToken, async (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required" });
    const { newUsername, newPassword } = req.body;

    if (!newUsername || !newPassword) {
        return res.status(400).json({ error: "New username and password required" });
    }

    try {
        const hash = await bcrypt.hash(newPassword, 10);
        db.run("UPDATE users SET username = ?, password = ? WHERE id = ?", [newUsername.trim(), hash, req.user.id], function(err) {
            if (err) return res.status(500).json({ error: "Username already taken or database error" });
            res.json({ message: "Admin credentials updated successfully! Please re-login." });
        });
    } catch(e) {
        res.status(500).json({ error: "Password encryption error" });
    }
});

// --- ADMIN USER MANAGEMENT & AUDIT CONTROL ---

app.get('/api/users', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required" });
    
    db.all("SELECT id, username, phone, role, zones, status FROM users WHERE role != 'ADMIN'", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        const parsedRows = rows.map(r => {
            let z = [];
            try { z = JSON.parse(r.zones); } catch(e) { z = [r.zones]; }
            return { ...r, zones: z };
        });
        res.json(parsedRows);
    });
});

app.post('/api/users', authenticateToken, async (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required" });
    
    const { username, phone, password, zones } = req.body;
    if (!username || !phone || !password || !zones || !Array.isArray(zones) || zones.length === 0) {
        return res.status(400).json({ error: "Username, phone, password, and at least 1 zone required." });
    }

    try {
        const hash = await bcrypt.hash(password, 10);
        const zonesJson = JSON.stringify(zones.map(z => z.trim().toUpperCase()));

        db.run("INSERT INTO users (username, phone, password, role, zones, status) VALUES (?, ?, ?, 'OPERATOR', ?, 1)", 
            [username.trim(), phone.trim(), hash, zonesJson], 
            function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE')) return res.status(400).json({ error: "Username already exists." });
                    return res.status(500).json({ error: err.message });
                }
                res.json({ message: "User assigned successfully!" });
            }
        );
    } catch (e) {
        res.status(500).json({ error: "Encryption error" });
    }
});

app.put('/api/users/:id/status', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required" });
    db.run("UPDATE users SET status = ? WHERE id = ?", [req.body.status, req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "User status updated" });
    });
});

app.get('/api/admin/audit-logs', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required" });
    db.all("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// --- MASTER DRUG DIRECTORY ROUTES ---

app.get('/api/master-drugs', authenticateToken, (req, res) => {
    const targetZone = req.query.zone;
    if (!targetZone) return res.status(400).json({ error: "Zone parameter required" });

    db.all("SELECT drug_name FROM master_drugs WHERE zone = ? ORDER BY drug_name ASC", [targetZone], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows.map(r => r.drug_name));
    });
});

app.post('/api/master-drugs', authenticateToken, (req, res) => {
    const { drug_name, zone } = req.body;
    if (!drug_name || !zone) return res.status(400).json({ error: "Drug name and zone required" });
    
    const name = drug_name.trim().toUpperCase();

    db.run("INSERT OR IGNORE INTO master_drugs (zone, drug_name) VALUES (?, ?)", [zone, name], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Drug registered successfully" });
    });
});

// Edit drug name in Master Directory (Cascades to history and daily totals)
app.put('/api/master-drugs/rename', authenticateToken, (req, res) => {
    const { oldName, newName, zone } = req.body;
    if (!oldName || !newName || !zone) return res.status(400).json({ error: "Old name, new name, and zone required" });

    const formattedOld = oldName.trim().toUpperCase();
    const formattedNew = newName.trim().toUpperCase();

    db.serialize(() => {
        db.run("UPDATE master_drugs SET drug_name = ? WHERE drug_name = ? AND zone = ?", [formattedNew, formattedOld, zone]);
        db.run("UPDATE dispenses SET drug_name = ? WHERE drug_name = ? AND zone = ?", [formattedNew, formattedOld, zone], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: `Successfully updated ${formattedOld} to ${formattedNew} across all system logs.` });
        });
    });
});

// Master Directory Import Routine (Supports Merge or Reset)
app.post('/api/master-drugs/import', authenticateToken, (req, res) => {
    const { mode, drugs, zone } = req.body; // mode: 'reset' or 'merge'
    if (!zone || !Array.isArray(drugs)) return res.status(400).json({ error: "Invalid data format or missing zone" });

    db.serialize(() => {
        if (mode === 'reset') {
            db.run("DELETE FROM master_drugs WHERE zone = ?", [zone]);
        }

        const stmt = db.prepare("INSERT OR IGNORE INTO master_drugs (zone, drug_name) VALUES (?, ?)");
        drugs.forEach(d => {
            if (typeof d === 'string' && d.trim().length > 0) {
                stmt.run(zone, d.trim().toUpperCase());
            }
        });
        stmt.finalize((err) => {
            if (err) return res.status(500).json({ error: "Import failed" });
            res.json({ message: `Master directory successfully ${mode === 'reset' ? 'reset and loaded' : 'merged'} with ${drugs.length} items.` });
        });
    });
});

// --- DISPENSE & TODAY'S TOTAL LOGS ---

app.post('/api/dispense', authenticateToken, (req, res) => {
    const { drug_name, qty, zone } = req.body;
    if (!drug_name || !qty || !zone) return res.status(400).json({ error: "Drug, quantity, and zone required" });

    const drugName = drug_name.trim().toUpperCase();

    db.run("INSERT INTO dispenses (zone, drug_name, qty, entered_by) VALUES (?, ?, ?, ?)", 
        [zone, drugName, parseInt(qty), req.user.username], 
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: "Entry recorded" });
        }
    );
});

app.get('/api/dispense/sync', authenticateToken, (req, res) => {
    const targetZone = req.query.zone;
    if (!targetZone) return res.status(400).json({ error: "Zone required" });

    db.all("SELECT * FROM dispenses WHERE zone = ? ORDER BY id DESC LIMIT 500", [targetZone], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// Edit or Undo recent dispense amount
app.put('/api/dispense/:id', authenticateToken, (req, res) => {
    const { qty } = req.body;
    if (isNaN(qty)) return res.status(400).json({ error: "Valid quantity required" });

    db.run("UPDATE dispenses SET qty = ? WHERE id = ?", [parseInt(qty), req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Dispense amount updated successfully" });
    });
});

app.delete('/api/dispense/:id', authenticateToken, (req, res) => {
    db.run("DELETE FROM dispenses WHERE id = ?", [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Record deleted" });
    });
});

// Today's Total / Dispense History Import Routine
app.post('/api/dispense/import', authenticateToken, (req, res) => {
    const { mode, records, zone } = req.body; // mode: 'reset' or 'merge', records: [{drug_name, qty}]
    if (!zone || !Array.isArray(records)) return res.status(400).json({ error: "Invalid data format or missing zone" });

    db.serialize(() => {
        if (mode === 'reset') {
            db.run("DELETE FROM dispenses WHERE zone = ?", [zone]);
        }

        const stmt = db.prepare("INSERT INTO dispenses (zone, drug_name, qty, entered_by) VALUES (?, ?, ?, ?)");
        records.forEach(r => {
            if (r.drug_name && !isNaN(r.qty)) {
                stmt.run(zone, r.drug_name.trim().toUpperCase(), parseInt(r.qty), req.user.username);
            }
        });
        stmt.finalize((err) => {
            if (err) return res.status(500).json({ error: "Import failed" });
            res.json({ message: `Today's Totals successfully ${mode === 'reset' ? 'reset and imported' : 'merged'} with ${records.length} entries.` });
        });
    });
});

// --- SINGLE PAGE FRONTEND CONSOLE ---

app.get('/', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHARMA-SYNC PRO | CLINICAL ENTERPRISE DIRECTORY</title>
    
    <!-- Dependencies for PDF and Excel Processing -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.23/jspdf.plugin.autotable.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    
    <style>
        :root {
            --bg: #f0f4f9;
            --card-bg: #ffffff;
            --primary: #0284c7;
            --primary-hover: #0369a1;
            --secondary: #6366f1;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --text-main: #0f172a;
            --text-muted: #64748b;
            --shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.05);
        }

        body { font-family: 'Plus Jakarta Sans', sans-serif; background-color: var(--bg); color: var(--text-main); margin: 0; padding: 20px; }
        .container { max-width: 1550px; margin: auto; }

        .header-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; background: linear-gradient(135deg, #ffffff 0%, #e0f2fe 100%); padding: 18px 28px; border-radius: 16px; border: 2px solid #bae6fd; box-shadow: var(--shadow); }
        .panel { background: var(--card-bg); padding: 22px; border-radius: 16px; border: 1px solid #e2e8f0; margin-bottom: 20px; box-shadow: var(--shadow); }
        .panel h2 { font-size: 15px; font-weight: 800; margin-top: 0; margin-bottom: 16px; color: var(--primary); border-bottom: 2px solid #f1f5f9; padding-bottom: 10px; text-transform: uppercase; display: flex; justify-content: space-between; align-items: center; }

        input, select, textarea { width: 100%; padding: 10px 12px; border: 2px solid #e2e8f0; border-radius: 10px; font-size: 13px; font-weight: 600; box-sizing: border-box; margin-bottom: 10px; background: #f8fafc; transition: 0.2s; }
        input:focus, select:focus { outline: none; border-color: var(--primary); background: #ffffff; }

        .primary-btn { background: var(--primary); color: white; padding: 10px 14px; border: none; border-radius: 10px; cursor: pointer; font-weight: 700; width: 100%; transition: 0.2s; font-size: 13px; }
        .primary-btn:hover { background: var(--primary-hover); }

        .app-grid { display: grid; grid-template-columns: 380px 1fr 400px; gap: 20px; }
        @media (max-width: 1250px) { .app-grid { grid-template-columns: 1fr; } }

        .table-wrap { max-height: 300px; overflow-y: auto; border: 2px solid #e2e8f0; border-radius: 10px; background: #ffffff; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th { background: #f8fafc; padding: 10px; text-align: left; color: var(--text-muted); font-weight: 700; position: sticky; top: 0; border-bottom: 2px solid #e2e8f0; }
        td { padding: 8px 10px; border-bottom: 1px solid #f1f5f9; }

        .badge { background: #e0f2fe; color: #0284c7; padding: 4px 8px; border-radius: 6px; font-weight: 800; font-size: 11px; }
        .action-btn { cursor: pointer; font-size: 11px; font-weight: 700; border: none; padding: 4px 8px; border-radius: 6px; }

        /* Overlays */
        #loginOverlay, #zoneSelectModal, #importModal { position: fixed; inset: 0; background: rgba(15, 23, 42, 0.7); display: grid; place-items: center; z-index: 2000; backdrop-filter: blur(4px); }
        .modal-box { width: 380px; background: #ffffff; padding: 30px; border-radius: 20px; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25); }

        .legal-footer { margin-top: 30px; padding: 15px; text-align: center; font-size: 12px; color: var(--text-muted); font-weight: 700; border-top: 2px dashed #cbd5e1; }
    </style>
</head>
<body>

<!-- LOGIN MODAL -->
<div id="loginOverlay">
    <div class="modal-box">
        <h2 style="text-align:center; color:var(--primary); font-size:24px; font-weight:800; margin-top:0;">PHARMA<span style="color:var(--secondary)">SYNC</span></h2>
        <p style="text-align:center; color:var(--text-muted); font-size:12px; margin-top:-10px; margin-bottom:20px;">System Architecture by Debanjan Singha</p>
        <input type="text" id="loginUser" placeholder="Username or Phone Number">
        <input type="password" id="loginPass" placeholder="Password">
        <button class="primary-btn" style="height:45px;" onclick="login()">SECURE LOG IN</button>
        <p id="errMsg" style="color:var(--danger); font-size:12px; text-align:center; margin-top:12px; font-weight:700;"></p>
    </div>
</div>

<!-- MULTI-ZONE SELECTION MODAL -->
<div id="zoneSelectModal" style="display:none;">
    <div class="modal-box">
        <h2 style="color:var(--primary); font-size:18px; margin-top:0;">🌐 Select Assigned Zone</h2>
        <p style="font-size:12px; color:var(--text-muted);">Select active workspace to proceed:</p>
        <select id="userZoneDropdown" style="height:40px;"></select>
        <button class="primary-btn" onclick="confirmZoneSelection()">ENTER WORKSPACE</button>
    </div>
</div>

<!-- DUAL IMPORT MODAL (JSON / EXCEL) -->
<div id="importModal" style="display:none;">
    <div class="modal-box" style="width:450px;">
        <h2 id="importTitle" style="color:var(--primary); font-size:16px; margin-top:0;">📥 Import File</h2>
        <p style="font-size:12px; color:var(--text-muted);">Upload .JSON or .XLSX / .XLS File</p>
        <input type="file" id="importFileInput" accept=".json, .xlsx, .xls">
        
        <div style="display:flex; gap:8px; margin-top:15px;">
            <button class="primary-btn" style="background:var(--success);" onclick="processImport('merge')">Merge with Existing</button>
            <button class="primary-btn" style="background:var(--danger);" onclick="processImport('reset')">Reset & Add New</button>
            <button class="primary-btn" style="background:#64748b;" onclick="closeImportModal()">Cancel</button>
        </div>
    </div>
</div>

<div class="container">
    <!-- TOP HEADER -->
    <div class="header-bar">
        <div>
            <h1 style="margin:0; font-size:22px; font-weight:800; display:inline-block;">PHARMA<span style="color:var(--primary)">SYNC</span> PRO</h1>
            <span id="activeZoneBadge" class="badge" style="margin-left:12px;">ZONE: UNASSIGNED</span>
        </div>
        <div style="display:flex; align-items:center; gap:12px;">
            <span id="uNameDisplay" style="font-weight:800; color:var(--primary); background:#ffffff; padding:6px 14px; border-radius:8px; border:1px solid #bae6fd;"></span>
            <button onclick="logout()" style="background:var(--danger); color:white; border:none; padding:8px 14px; border-radius:8px; cursor:pointer; font-weight:700; font-size:12px;">LOGOUT</button>
        </div>
    </div>

    <!-- MAIN APP INTERFACE -->
    <div class="app-grid">
        
        <!-- LEFT COLUMN: MASTER DIRECTORY & OPERATOR TOOLING -->
        <div>
            <!-- MASTER DIRECTORY PANEL -->
            <div class="panel">
                <h2>
                    <span>📦 Master Directory</span>
                    <button id="masterImportBtn" style="display:none; background:var(--secondary); color:white; border:none; padding:4px 8px; border-radius:6px; font-size:11px; cursor:pointer;" onclick="openImportModal('master')">📥 Import</button>
                </h2>
                
                <div id="operatorMasterControls">
                    <input type="text" id="newDrugName" placeholder="Register New Drug Name...">
                    <button class="primary-btn" onclick="registerDrug()">ADD TO MASTER</button>
                </div>

                <input type="text" style="margin-top:12px" onkeyup="filterTable('masterBody', this.value)" placeholder="Search master list...">
                <div class="table-wrap" style="max-height: 250px;">
                    <table>
                        <thead><tr><th>Drug Name</th><th>Actions</th></tr></thead>
                        <tbody id="masterBody"></tbody>
                    </table>
                </div>

                <div style="margin-top:10px;">
                    <button class="primary-btn" style="background:#64748b;" onclick="downloadMasterDirectoryBackup()">💾 Backup Master Directory (JSON)</button>
                </div>
            </div>

            <!-- ADMIN CONSOLE (VISIBLE SOLELY TO ADMIN) -->
            <div id="adminPanel" class="panel" style="display:none; border:2px solid #c7d2fe;">
                <h2>👑 Admin Workspace & Users</h2>
                
                <!-- Admin Self Credential Editing -->
                <div style="background:#f1f5f9; padding:10px; border-radius:10px; margin-bottom:15px;">
                    <span style="font-size:11px; font-weight:800; color:var(--primary);">UPDATE ADMIN CREDENTIALS</span>
                    <input type="text" id="admNewU" placeholder="New Admin Username" style="margin-top:5px;">
                    <input type="password" id="admNewP" placeholder="New Password">
                    <button class="primary-btn" style="background:var(--secondary);" onclick="updateAdminProfile()">UPDATE ADMIN LOGIN</button>
                </div>

                <!-- User Creation -->
                <span style="font-size:11px; font-weight:800; color:var(--text-muted);">ASSIGN NEW OPERATOR</span>
                <input type="text" id="nuName" placeholder="Full Name">
                <input type="text" id="nuPhone" placeholder="Phone Number">
                <input type="password" id="nuPass" placeholder="Password">
                <input type="text" id="nuZones" placeholder="Assigned Zones (Comma separated e.g. NORTH, SOUTH)">
                <button class="primary-btn" style="background:var(--success); margin-bottom:15px;" onclick="createUser()">CREATE USER</button>

                <span style="font-size:11px; font-weight:800; color:var(--text-muted);">USER DIRECTORY & ACCESS CONTROL</span>
                <div class="table-wrap" style="max-height: 140px;">
                    <table>
                        <thead><tr><th>User / Phone</th><th>Zones</th><th>Access</th></tr></thead>
                        <tbody id="adminUserList"></tbody>
                    </table>
                </div>

                <span style="font-size:11px; font-weight:800; color:var(--text-muted); margin-top:10px; display:block;">LOGIN / LOGOUT ACTIVITY LOGS</span>
                <div class="table-wrap" style="max-height: 140px;">
                    <table>
                        <thead><tr><th>Time</th><th>User</th><th>Action</th></tr></thead>
                        <tbody id="auditLogBody"></tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- CENTER COLUMN: DISPENSE CONSOLE & TODAY'S TOTALS (OPERATORS ONLY) -->
        <div id="operatorWorkspace" class="panel">
            <h2>🛒 Dispense Console</h2>
            <div style="display: grid; grid-template-columns: 1fr 120px; gap: 10px;">
                <input type="text" id="searchDrug" list="drugList" placeholder="Select or Type Drug...">
                <input type="number" id="dispenseAmount" placeholder="Qty">
            </div>
            <datalist id="drugList"></datalist>

            <button class="primary-btn" style="background:var(--success); height:40px; font-size:14px;" onclick="dispenseDrug()">RECORD DISPENSE</button>

            <h2>
                <span>📊 Today's Cumulative Totals</span>
                <button style="background:var(--secondary); color:white; border:none; padding:4px 8px; border-radius:6px; font-size:11px; cursor:pointer;" onclick="openImportModal('dispense')">📥 Import Totals</button>
            </h2>
            <input type="text" onkeyup="filterTable('dailyBody', this.value)" placeholder="Filter daily total...">
            <div class="table-wrap" style="max-height: 300px;">
                <table>
                    <thead><tr><th>Drug Name</th><th>Total Dispensed</th></tr></thead>
                    <tbody id="dailyBody"></tbody>
                </table>
            </div>
        </div>

        <!-- RIGHT COLUMN: LIVE RECENT HISTORY & REPORTING -->
        <div id="reportingWorkspace">
            <div class="panel">
                <h2>🕒 Recent Activity History</h2>
                <div class="table-wrap" style="max-height: 280px;">
                    <table>
                        <thead><tr><th>Time</th><th>Drug & Qty</th><th>By</th><th>Action</th></tr></thead>
                        <tbody id="historyBody"></tbody>
                    </table>
                </div>
            </div>

            <div class="panel">
                <h2>📄 Mandatory PDF & Backup Exports</h2>
                <input type="text" id="pdfRemarks" placeholder="Enter mandatory remarks prior to download...">
                
                <button class="primary-btn" style="background:var(--danger); margin-bottom:10px;" onclick="generatePdfReport()">EXPORT PDF REPORT</button>
                <button class="primary-btn" style="background:var(--primary); margin-bottom:10px;" onclick="downloadDispenseHistoryBackup()">EXPORT HISTORY BACKUP (JSON)</button>
                <button class="primary-btn" style="background:var(--secondary);" onclick="downloadFullZoneBackup()">EXPORT COMPLETE ZONE BACKUP (JSON)</button>
            </div>
        </div>

    </div>

    <div class="legal-footer">
        © 2026 <b>Debanjan Singha</b>. All Legal Credits Reserved. <br>
        Unauthorized replication, distribution, or execution without express written permission is strictly prohibited and subject to legal prosecution.
    </div>
</div>

<script>
    let token = localStorage.getItem('ps_token');
    let role = localStorage.getItem('ps_role');
    let user = localStorage.getItem('ps_user');
    let userZones = JSON.parse(localStorage.getItem('ps_zones') || "[]");
    let activeZone = localStorage.getItem('ps_active_zone') || "";

    let masterList = [];
    let liveDispenseLog = [];
    let dailyTotals = {};
    let activeImportTarget = "";

    // AUTHENTICATION
    async function login() {
        const u = document.getElementById('loginUser').value.trim();
        const p = document.getElementById('loginPass').value.trim();
        
        const res = await fetch('/api/login', { 
            method: 'POST', 
            headers: {'Content-Type': 'application/json'}, 
            body: JSON.stringify({username: u, password: p}) 
        });
        
        const d = await res.json();
        if(res.ok) {
            localStorage.setItem('ps_token', d.token);
            localStorage.setItem('ps_role', d.role);
            localStorage.setItem('ps_user', d.username);
            localStorage.setItem('ps_zones', JSON.stringify(d.zones));
            
            token = d.token; role = d.role; user = d.username; userZones = d.zones;

            if(role === 'OPERATOR') {
                if(userZones.length > 1) {
                    promptZoneSelection(userZones);
                } else {
                    setActiveZone(userZones[0] || 'DEFAULT');
                }
            } else {
                setActiveZone('ALL');
            }
        } else {
            document.getElementById('errMsg').innerText = d.error || d.message || "Login failed";
        }
    }

    function promptZoneSelection(zones) {
        document.getElementById('loginOverlay').style.display = 'none';
        const dropdown = document.getElementById('userZoneDropdown');
        dropdown.innerHTML = zones.map(z => `<option value="${z}">${z}</option>`).join('');
        document.getElementById('zoneSelectModal').style.display = 'grid';
    }

    function confirmZoneSelection() {
        const selected = document.getElementById('userZoneDropdown').value;
        document.getElementById('zoneSelectModal').style.display = 'none';
        setActiveZone(selected);
    }

    function setActiveZone(zName) {
        activeZone = zName;
        localStorage.setItem('ps_active_zone', zName);
        location.reload();
    }

    async function logout() {
        if(token) {
            await fetch('/api/logout', { 
                method: 'POST', 
                headers: {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'},
                body: JSON.stringify({ zone: activeZone })
            });
        }
        localStorage.clear();
        location.reload();
    }

    // MASTER DIRECTORY MANAGEMENT
    async function loadMasterDrugs() {
        if(!activeZone) return;
        const res = await fetch('/api/master-drugs?zone=' + encodeURIComponent(activeZone), { 
            headers: {'Authorization': 'Bearer ' + token} 
        });
        if(res.ok) {
            masterList = await res.json();
            document.getElementById('masterBody').innerHTML = masterList.map(item => `
                <tr>
                    <td><b>${item}</b></td>
                    <td>
                        <button class="action-btn" style="background:#e0f2fe; color:#0284c7;" onclick="renameDrug('${item}')">Edit</button>
                    </td>
                </tr>
            `).join('');
            document.getElementById('drugList').innerHTML = masterList.map(m => `<option value="${m}">`).join('');
        }
    }

    async function registerDrug() {
        const input = document.getElementById('newDrugName');
        const name = input.value.trim().toUpperCase();
        if(!name) return alert("Enter valid drug name.");

        const res = await fetch('/api/master-drugs', {
            method: 'POST',
            headers: {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'},
            body: JSON.stringify({ drug_name: name, zone: activeZone })
        });
        if(res.ok) { input.value = ''; loadMasterDrugs(); }
    }

    async function renameDrug(oldName) {
        const newName = prompt(`Rename ${oldName} across master directory and all recorded history:`, oldName);
        if(!newName || newName.trim().toUpperCase() === oldName) return;

        const res = await fetch('/api/master-drugs/rename', {
            method: 'PUT',
            headers: {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'},
            body: JSON.stringify({ oldName, newName: newName.trim().toUpperCase(), zone: activeZone })
        });

        if(res.ok) {
            loadMasterDrugs();
            syncData();
        }
    }

    // DISPENSE CONSOLE
    async function dispenseDrug() {
        const drugInput = document.getElementById('searchDrug');
        const qtyInput = document.getElementById('dispenseAmount');

        const drug_name = drugInput.value.trim();
        const qty = parseInt(qtyInput.value, 10);

        if(!drug_name || isNaN(qty) || qty <= 0) return alert("Select drug and enter positive quantity.");

        const res = await fetch('/api/dispense', {
            method: 'POST',
            headers: {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'},
            body: JSON.stringify({ drug_name, qty, zone: activeZone })
        });

        if(res.ok) {
            drugInput.value = ''; qtyInput.value = '';
            syncData();
        }
    }

    async function editDispense(id, currentQty) {
        const newQty = prompt("Enter updated quantity (Set 0 to delete):", currentQty);
        if(newQty === null) return;
        
        if(parseInt(newQty) === 0) {
            await fetch('/api/dispense/' + id, { method: 'DELETE', headers: {'Authorization': 'Bearer ' + token} });
        } else {
            await fetch('/api/dispense/' + id, {
                method: 'PUT',
                headers: {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'},
                body: JSON.stringify({ qty: newQty })
            });
        }
        syncData();
    }

    // DATA SYNC & TOTALS RENDERING
    async function syncData() {
        if(!token || !activeZone) return;

        const res = await fetch('/api/dispense/sync?zone=' + encodeURIComponent(activeZone), {
            headers: {'Authorization': 'Bearer ' + token}
        });

        if(res.status === 403) {
            alert("ERROR! PLEASE CONTACT TO THE ADMIN");
            return logout();
        }

        if(res.ok) {
            liveDispenseLog = await res.json();
            renderDispenseHistory();
            calculateAndRenderDailyTotals();
        }

        if(role === 'ADMIN') {
            loadAdminUserMetrics();
            loadAdminAuditLogs();
        }
    }

    function renderDispenseHistory() {
        document.getElementById('historyBody').innerHTML = liveDispenseLog.map(item => `
            <tr>
                <td style="font-size:10px; color:var(--text-muted);">${new Date(item.timestamp).toLocaleTimeString()}</td>
                <td><b>${item.drug_name}</b> <span class="badge">${item.qty}</span></td>
                <td>${item.entered_by}</td>
                <td>
                    <button class="action-btn" style="background:#fef3c7; color:#d97706;" onclick="editDispense(${item.id}, ${item.qty})">Edit</button>
                </td>
            </tr>
        `).join('');
    }

    function calculateAndRenderDailyTotals() {
        dailyTotals = {};
        liveDispenseLog.forEach(row => {
            dailyTotals[row.drug_name] = (dailyTotals[row.drug_name] || 0) + Number(row.qty);
        });

        document.getElementById('dailyBody').innerHTML = Object.keys(dailyTotals).sort().map(drug => `
            <tr>
                <td><b>${drug}</b></td>
                <td><span class="badge" style="background:#dcfce7; color:#15803d; font-size:12px;">${dailyTotals[drug]}</span></td>
            </tr>
        `).join('');
    }

    // DUAL IMPORT SYSTEM (JSON & EXCEL)
    function openImportModal(target) {
        activeImportTarget = target;
        document.getElementById('importTitle').innerText = target === 'master' ? "📥 Import Master Directory" : "📥 Import Today's Totals";
        document.getElementById('importModal').style.display = 'grid';
    }

    function closeImportModal() {
        document.getElementById('importModal').style.display = 'none';
        document.getElementById('importFileInput').value = '';
    }

    async function processImport(mode) {
        const fileInput = document.getElementById('importFileInput');
        if(!fileInput.files.length) return alert("Select a JSON or Excel file first.");

        const file = fileInput.files[0];
        const fileName = file.name.toLowerCase();

        let parsedData = [];

        if(fileName.endsWith('.json')) {
            const text = await file.text();
            parsedData = JSON.parse(text);
        } else if(fileName.endsWith('.xlsx') || fileName.endsWith('.xls')) {
            const data = await file.arrayBuffer();
            const workbook = XLSX.read(data, {type: 'array'});
            const firstSheet = workbook.Sheets[workbook.SheetNames[0]];
            parsedData = XLSX.utils.sheet_to_json(firstSheet);
        } else {
            return alert("Unsupported file format. Please upload .json, .xlsx, or .xls");
        }

        let endpoint = activeImportTarget === 'master' ? '/api/master-drugs/import' : '/api/dispense/import';
        let payload = {};

        if(activeImportTarget === 'master') {
            // Standardize array of strings
            const drugs = parsedData.map(d => typeof d === 'string' ? d : (d.drug_name || d.DRUG_NAME || Object.values(d)[0]));
            payload = { mode, drugs, zone: activeZone };
        } else {
            // Standardize array of {drug_name, qty}
            const records = parsedData.map(r => ({
                drug_name: r.drug_name || r.DRUG_NAME || Object.values(r)[0],
                qty: r.qty || r.QTY || Object.values(r)[1] || 1
            }));
            payload = { mode, records, zone: activeZone };
        }

        const res = await fetch(endpoint, {
            method: 'POST',
            headers: {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });

        if(res.ok) {
            alert((await res.json()).message);
            closeImportModal();
            loadMasterDrugs();
            syncData();
        }
    }

    // ADMIN CONTROLS
    async function updateAdminProfile() {
        const newUsername = document.getElementById('admNewU').value.trim();
        const newPassword = document.getElementById('admNewP').value.trim();

        const res = await fetch('/api/admin/profile', {
            method: 'PUT',
            headers: {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'},
            body: JSON.stringify({ newUsername, newPassword })
        });
        
        const d = await res.json();
        if(res.ok) {
            alert(d.message);
            logout();
        } else {
            alert(d.error);
        }
    }

    async function createUser() {
        const username = document.getElementById('nuName').value.trim();
        const phone = document.getElementById('nuPhone').value.trim();
        const password = document.getElementById('nuPass').value.trim();
        const zones = document.getElementById('nuZones').value.split(',').map(z => z.trim()).filter(z => z);

        const res = await fetch('/api/users', {
            method: 'POST',
            headers: {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'},
            body: JSON.stringify({ username, phone, password, zones })
        });

        if(res.ok) {
            document.getElementById('nuName').value = ''; document.getElementById('nuPhone').value = '';
            document.getElementById('nuPass').value = ''; document.getElementById('nuZones').value = '';
            loadAdminUserMetrics();
        } else {
            alert((await res.json()).error);
        }
    }

    async function loadAdminUserMetrics() {
        const res = await fetch('/api/users', { headers: {'Authorization': 'Bearer ' + token} });
        if(res.ok) {
            const users = await res.json();
            document.getElementById('adminUserList').innerHTML = users.map(u => `
                <tr>
                    <td><b>${u.username}</b><br><small>${u.phone}</small></td>
                    <td><small>${u.zones.join(', ')}</small></td>
                    <td>
                        <button class="action-btn" style="background:${u.status === 1 ? '#fee2e2' : '#dcfce7'}; color:${u.status === 1 ? '#ef4444' : '#15803d'};" onclick="toggleUserStatus(${u.id}, ${u.status === 1 ? 0 : 1})">
                            ${u.status === 1 ? 'TURN OFF' : 'TURN ON'}
                        </button>
                    </td>
                </tr>
            `).join('');
        }
    }

    async function toggleUserStatus(id, status) {
        await fetch(`/api/users/${id}/status`, {
            method: 'PUT',
            headers: {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'},
            body: JSON.stringify({ status })
        });
        loadAdminUserMetrics();
    }

    async function loadAdminAuditLogs() {
        const res = await fetch('/api/admin/audit-logs', { headers: {'Authorization': 'Bearer ' + token} });
        if(res.ok) {
            const logs = await res.json();
            document.getElementById('auditLogBody').innerHTML = logs.map(l => `
                <tr>
                    <td style="font-size:10px;">${new Date(l.timestamp).toLocaleTimeString()}</td>
                    <td><b>${l.username}</b></td>
                    <td><span class="badge">${l.action}</span></td>
                </tr>
            `).join('');
        }
    }

    // BACKUP & MANDATORY PDF EXPORT ROUTINES
    function generatePdfReport() {
        const remarks = document.getElementById('pdfRemarks').value.trim();
        if(!remarks) return alert("ERROR: Remarks field is mandatory before generating PDF report.");

        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();

        // Header Section
        doc.setFontSize(16);
        doc.setTextColor(2, 132, 199);
        doc.text("PHARMA-SYNC PRO | CUMULATIVE DISPENSE REPORT", 14, 15);

        doc.setFontSize(10);
        doc.setTextColor(100, 116, 139);
        doc.text(`Date & Time: ${new Date().toLocaleString()}`, 14, 23);
        doc.text(`Zone Name: ${activeZone}`, 14, 29);
        doc.text(`Mandatory Remarks: ${remarks}`, 14, 35);

        // Daily Summary Table
        const tableData = Object.keys(dailyTotals).sort().map(drug => [drug, dailyTotals[drug]]);
        doc.autoTable({
            startY: 42,
            head: [['Drug Name', 'Total Quantity Dispensed']],
            body: tableData,
            theme: 'striped',
            headStyles: { fillColor: [2, 132, 199] }
        });

        // Footers on Every Page
        const pageCount = doc.internal.getNumberOfPages();
        for (let i = 1; i <= pageCount; i++) {
            doc.setPage(i);
            doc.setFontSize(9);
            doc.setTextColor(150, 150, 150);
            doc.text("Lead Developer: Debanjan Singha", 14, doc.internal.pageSize.height - 10);
            doc.text(`Page ${i} of ${pageCount}`, doc.internal.pageSize.width - 25, doc.internal.pageSize.height - 10);
        }

        doc.save(`Report_${activeZone}_${Date.now()}.pdf`);
    }

    function downloadJSON(data, fileName) {
        const remarks = document.getElementById('pdfRemarks').value.trim();
        if(!remarks) return alert("ERROR: Remarks field is mandatory prior to backup download.");

        const blob = new Blob([JSON.stringify({ remarks, zone: activeZone, exportDate: new Date(), data }, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = fileName;
        a.click();
    }

    function downloadMasterDirectoryBackup() {
        downloadJSON(masterList, `MasterDirectory_${activeZone}_Backup.json`);
    }

    function downloadDispenseHistoryBackup() {
        downloadJSON(liveDispenseLog, `DispenseHistory_${activeZone}_Backup.json`);
    }

    function downloadFullZoneBackup() {
        downloadJSON({ masterDirectory: masterList, dispenseHistory: liveDispenseLog, totals: dailyTotals }, `FullZone_${activeZone}_Backup.json`);
    }

    function filterTable(tableId, query) {
        const term = query.toLowerCase();
        const rows = document.getElementById(tableId).getElementsByTagName('tr');
        for (let r of rows) {
            r.style.display = r.innerText.toLowerCase().includes(term) ? '' : 'none';
        }
    }

    // INITIALIZATION
    window.onload = function() {
        if(token) {
            document.getElementById('loginOverlay').style.display = 'none';
            document.getElementById('uNameDisplay').innerText = user;
            document.getElementById('activeZoneBadge').innerText = "ZONE: " + activeZone;

            if(role === 'ADMIN') {
                document.getElementById('adminPanel').style.display = 'block';
                document.getElementById('masterImportBtn').style.display = 'inline-block';
                document.getElementById('operatorWorkspace').style.display = 'none';
            } else {
                loadMasterDrugs();
                syncData();
                setInterval(syncData, 5000); // 5-second live auto-sync
            }
        } else {
            document.getElementById('loginOverlay').style.display = 'grid';
        }
    };
</script>
</body>
</html>
    `);
});

app.listen(PORT, () => {
    console.log(`Pharma-Sync Pro Server actively running on http://localhost:${PORT}`);
});
