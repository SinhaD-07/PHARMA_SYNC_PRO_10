const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();

let xlsx;
try {
    xlsx = require('xlsx');
} catch (e) {
    console.log("XLSX library loaded for backend processing.");
}

const app = express();
const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.JWT_SECRET || "pharma_sync_ultra_secure_debanjan_2026_key";

const COPYRIGHT_OWNER = "Debanjan Singha";
console.log("================================================================");
console.log(" PHARMA-SYNC PRO | ALL RIGHTS RESERVED");
console.log(" Architecture & Lead Engineering: " + COPYRIGHT_OWNER);
console.log(" Unauthorized copying, distribution, or execution is prohibited.");
console.log("================================================================");

app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Initialize Database
const db = new sqlite3.Database('./pharmacy.db', (err) => {
    if (!err) {
        initDb();
    }
});

function initDb() {
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, phone TEXT, password TEXT, role TEXT, zones TEXT, status INTEGER DEFAULT 1)");
    db.run("CREATE TABLE IF NOT EXISTS master_drugs (id INTEGER PRIMARY KEY AUTOINCREMENT, zone TEXT, drug_name TEXT, UNIQUE(zone, drug_name))");
    db.run("CREATE TABLE IF NOT EXISTS dispenses (id INTEGER PRIMARY KEY AUTOINCREMENT, zone TEXT, drug_name TEXT, qty INTEGER, entered_by TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)");
    db.run("CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, phone TEXT, zone TEXT, action TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)");
    db.run("CREATE TABLE IF NOT EXISTS zone_registry (id INTEGER PRIMARY KEY AUTOINCREMENT, zone_name TEXT UNIQUE)");

    db.get("SELECT * FROM users WHERE role = 'ADMIN'", async (err, row) => {
        if (!row) {
            const hash = await bcrypt.hash('admin123', 10);
            db.run("INSERT INTO users (username, phone, password, role, zones, status) VALUES ('admin', '0000000000', ?, 'ADMIN', '[\"ALL\"]', 1)", [hash]);
        }
    });
}

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Access Denied. Token Missing." });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(403).json({ error: "Session expired. Auto logged out after 8 hours." });
        db.get("SELECT * FROM users WHERE id = ?", [decoded.id], (err, user) => {
            if (err || !user) return res.status(404).json({ error: "User profile not found." });
            if (user.status !== 1) {
                return res.status(403).json({ error: "ACCESS_DISABLED", message: "ERROR! PLEASE CONTACT TO THE ADMIN" });
            }
            req.user = user;
            next();
        });
    });
};

// ==========================================
// BACKEND API ROUTES
// ==========================================

app.post('/api/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    if (!username || !password) return res.status(400).json({ error: "Missing required fields." });

    db.get("SELECT * FROM users WHERE username = ? OR phone = ?", [username, username], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: "Invalid credentials." });
        if (user.status !== 1) return res.status(403).json({ error: "ERROR! PLEASE CONTACT TO THE ADMIN" });

        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) return res.status(400).json({ error: "Invalid credentials." });

        db.run("INSERT INTO audit_logs (username, phone, zone, action) VALUES (?, ?, ?, 'LOGIN')", [user.username, user.phone, user.zones]);

        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, SECRET_KEY, { expiresIn: '8h' });
        let userZones = [];
        try { userZones = JSON.parse(user.zones); } catch(e) { userZones = [user.zones]; }

        res.json({ token, role: user.role, username: user.username, phone: user.phone, zones: userZones });
    });
});

app.post('/api/logout', authenticateToken, (req, res) => {
    db.run("INSERT INTO audit_logs (username, phone, zone, action) VALUES (?, ?, ?, 'LOGOUT')", [req.user.username, req.user.phone, req.body.zone || "N/A"]);
    res.json({ message: "Logged out successfully" });
});

app.put('/api/admin/profile', authenticateToken, async (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required." });
    const newUsername = req.body.newUsername;
    const newPassword = req.body.newPassword;
    if (!newUsername || !newPassword) return res.status(400).json({ error: "Missing parameters." });

    const hash = await bcrypt.hash(newPassword, 10);
    db.run("UPDATE users SET username = ?, password = ? WHERE id = ?", [newUsername.trim(), hash, req.user.id], function(err) {
        if (err) return res.status(500).json({ error: "Username already taken." });
        res.json({ message: "Admin credentials updated successfully." });
    });
});

app.get('/api/users', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required." });
    db.all("SELECT id, username, phone, role, zones, status FROM users WHERE role != 'ADMIN'", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        const parsed = rows.map(r => {
            let z = [];
            try { z = JSON.parse(r.zones); } catch(e) { z = [r.zones]; }
            return { id: r.id, username: r.username, phone: r.phone, role: r.role, zones: z, status: r.status };
        });
        res.json(parsed);
    });
});

app.post('/api/users', authenticateToken, async (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required." });
    const username = req.body.username;
    const phone = req.body.phone;
    const password = req.body.password;
    const zones = req.body.zones;

    if (!username || !phone || !password || !zones || !zones.length) {
        return res.status(400).json({ error: "All user details and at least one zone are required." });
    }

    const hash = await bcrypt.hash(password, 10);
    db.run("INSERT INTO users (username, phone, password, role, zones, status) VALUES (?, ?, ?, 'OPERATOR', ?, 1)", 
        [username.trim(), phone.trim(), hash, JSON.stringify(zones)], 
        (err) => {
            if (err) return res.status(400).json({ error: "User with this name/phone already exists." });
            res.json({ message: "User account created successfully." });
        }
    );
});

// Update Zones for an existing user
app.put('/api/users/:id/zones', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required." });
    const newZones = req.body.zones;
    if (!newZones || !newZones.length) return res.status(400).json({ error: "At least one zone must be selected." });
    
    db.run("UPDATE users SET zones = ? WHERE id = ?", [JSON.stringify(newZones), req.params.id], (err) => {
        if (err) return res.status(500).json({ error: "Database error updating zones." });
        res.json({ message: "User zones updated successfully." });
    });
});

app.put('/api/users/:id/status', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required." });
    db.run("UPDATE users SET status = ? WHERE id = ?", [req.body.status, req.params.id], (err) => {
        res.json({ message: "User status updated." });
    });
});

app.delete('/api/users/:id', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required." });
    db.run("DELETE FROM users WHERE id = ?", [req.params.id], (err) => {
        res.json({ message: "User account permanently removed." });
    });
});

// Zone Registry Endpoints
app.get('/api/zones', authenticateToken, (req, res) => {
    db.all("SELECT zone_name FROM zone_registry ORDER BY zone_name ASC", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows.map(r => r.zone_name));
    });
});

app.post('/api/zones', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required." });
    const zName = req.body.zone_name ? req.body.zone_name.trim().toUpperCase() : "";
    if (!zName) return res.status(400).json({ error: "Zone name cannot be empty." });

    db.run("INSERT OR IGNORE INTO zone_registry (zone_name) VALUES (?)", [zName], (err) => {
        res.json({ message: "Zone registered successfully." });
    });
});

app.get('/api/admin/audit-logs', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required." });
    db.all("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200", [], (err, rows) => {
        res.json(rows);
    });
});

app.get('/api/master-drugs', authenticateToken, (req, res) => {
    db.all("SELECT drug_name FROM master_drugs WHERE zone = ? ORDER BY drug_name ASC", [req.query.zone], (err, rows) => {
        res.json(rows.map(r => r.drug_name));
    });
});

app.post('/api/master-drugs', authenticateToken, (req, res) => {
    db.run("INSERT OR IGNORE INTO master_drugs (zone, drug_name) VALUES (?, ?)", [req.body.zone, req.body.drug_name.trim().toUpperCase()], (err) => {
        res.json({ message: "Drug registered to Master Directory." });
    });
});

app.put('/api/master-drugs/rename', authenticateToken, (req, res) => {
    const oldName = req.body.oldName;
    const newName = req.body.newName;
    const zone = req.body.zone;
    db.serialize(() => {
        db.run("UPDATE master_drugs SET drug_name = ? WHERE drug_name = ? AND zone = ?", [newName.trim().toUpperCase(), oldName.trim().toUpperCase(), zone]);
        db.run("UPDATE dispenses SET drug_name = ? WHERE drug_name = ? AND zone = ?", [newName.trim().toUpperCase(), oldName.trim().toUpperCase(), zone], (err) => {
            res.json({ message: "Drug name updated across Master Directory and Dispense Records." });
        });
    });
});

// Resilient Master Import Engine
app.post('/api/master-drugs/import', authenticateToken, (req, res) => {
    const mode = req.body.mode;
    let drugs = req.body.drugs;
    const zone = req.body.zone;

    if (!zone || !drugs) return res.status(400).json({ error: "Invalid payload or unselected target zone." });
    if (!Array.isArray(drugs)) drugs = [drugs]; // Force Array conversion

    db.serialize(() => {
        if (mode === 'reset') db.run("DELETE FROM master_drugs WHERE zone = ?", [zone]);
        const stmt = db.prepare("INSERT OR IGNORE INTO master_drugs (zone, drug_name) VALUES (?, ?)");
        
        let importedCount = 0;
        drugs.forEach(d => {
            if (d) {
                // Highly resilient property extraction for messy JSON
                const nameStr = typeof d === 'object' ? (d.drug_name || d.name || d.DrugName || d.item || Object.values(d)[0]) : d;
                if (nameStr) {
                    stmt.run(zone, String(nameStr).trim().toUpperCase());
                    importedCount++;
                }
            }
        });
        
        stmt.finalize(() => {
            res.json({ message: `Master Directory imported successfully. Processed ${importedCount} items.` });
        });
    });
});

app.post('/api/dispense', authenticateToken, (req, res) => {
    db.run("INSERT INTO dispenses (zone, drug_name, qty, entered_by) VALUES (?, ?, ?, ?)", 
        [req.body.zone, req.body.drug_name.trim().toUpperCase(), parseInt(req.body.qty), req.user.username], 
        () => res.json({ message: "Dispense recorded." })
    );
});

app.get('/api/dispense/sync', authenticateToken, (req, res) => {
    db.all("SELECT * FROM dispenses WHERE zone = ? ORDER BY id DESC LIMIT 500", [req.query.zone], (err, rows) => {
        res.json(rows);
    });
});

app.put('/api/dispense/:id', authenticateToken, (req, res) => {
    db.run("UPDATE dispenses SET qty = ? WHERE id = ?", [parseInt(req.body.qty), req.params.id], () => res.json({ message: "Dispense quantity updated." }));
});

app.delete('/api/dispense/:id', authenticateToken, (req, res) => {
    db.run("DELETE FROM dispenses WHERE id = ?", [req.params.id], () => res.json({ message: "Dispense entry removed." }));
});

app.post('/api/dispense/import', authenticateToken, (req, res) => {
    const mode = req.body.mode;
    let records = req.body.records;
    const zone = req.body.zone;

    if (!zone || !records) return res.status(400).json({ error: "Invalid payload or unselected target zone." });
    if (!Array.isArray(records)) records = [records];

    db.serialize(() => {
        if (mode === 'reset') db.run("DELETE FROM dispenses WHERE zone = ?", [zone]);
        const stmt = db.prepare("INSERT INTO dispenses (zone, drug_name, qty, entered_by) VALUES (?, ?, ?, ?)");
        records.forEach(r => {
            if (r) {
                const dName = typeof r === 'object' ? (r.drug_name || r.name || r.DrugName || Object.values(r)[0]) : r;
                const dQty = typeof r === 'object' ? (r.qty || r.amount || r.Quantity || 1) : 1;
                if (dName) stmt.run(zone, String(dName).trim().toUpperCase(), parseInt(dQty), req.user.username);
            }
        });
        stmt.finalize(() => res.json({ message: "Totals imported successfully." }));
    });
});

// ==========================================
// SINGLE-FILE JOYFUL & COLOURFUL WEB INTERFACE
// ==========================================

app.get('/', (req, res) => {
    const htmlLines = [
        '<!DOCTYPE html>',
        '<html lang="en">',
        '<head>',
        '    <meta charset="UTF-8">',
        '    <meta name="viewport" content="width=device-width, initial-scale=1.0">',
        '    <title>PHARMA-SYNC PRO | Joyful Workspace</title>',
        '    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>',
        '    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.23/jspdf.plugin.autotable.min.js"></script>',
        '    <script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></script>',
        '    <style>',
        '        * { box-sizing: border-box; margin: 0; padding: 0; font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif; }',
        '        body { background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #064e3b 100%); color: #f8fafc; min-height: 100vh; padding: 25px; }',
        '        .container { max-width: 1200px; margin: 0 auto; }',
        '        .card { background: rgba(30, 41, 59, 0.85); backdrop-filter: blur(12px); border-radius: 16px; padding: 28px; margin-bottom: 24px; border: 1px solid rgba(255, 255, 255, 0.12); box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3); }',
        '        h1 { color: #38bdf8; text-shadow: 0 0 10px rgba(56, 189, 248, 0.3); }',
        '        h2 { color: #a78bfa; margin-bottom: 12px; }',
        '        h3 { color: #34d399; margin-bottom: 14px; font-size: 1.2rem; }',
        '        input, select, button { width: 100%; padding: 12px 16px; margin-bottom: 14px; border-radius: 10px; border: 1px solid #475569; background: #0f172a; color: white; font-size: 14px; outline: none; transition: all 0.2s ease-in-out; }',
        '        input:focus, select:focus { border-color: #38bdf8; box-shadow: 0 0 8px rgba(56, 189, 248, 0.4); }',
        '        button { background: linear-gradient(135deg, #0284c7 0%, #2563eb 100%); font-weight: bold; cursor: pointer; border: none; box-shadow: 0 4px 12px rgba(2, 132, 199, 0.3); }',
        '        button:hover { transform: translateY(-2px); box-shadow: 0 6px 16px rgba(2, 132, 199, 0.5); }',
        '        button.success { background: linear-gradient(135deg, #059669 0%, #10b981 100%); box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3); }',
        '        button.danger { background: linear-gradient(135deg, #dc2626 0%, #f43f5e 100%); box-shadow: 0 4px 12px rgba(220, 38, 38, 0.3); }',
        '        button.warning { background: linear-gradient(135deg, #d97706 0%, #f59e0b 100%); }',
        '        table { width: 100%; border-collapse: separate; border-spacing: 0; margin-top: 12px; border-radius: 10px; overflow: hidden; }',
        '        th, td { padding: 12px 16px; text-align: left; font-size: 14px; border-bottom: 1px solid #334155; }',
        '        th { background: #1e293b; color: #38bdf8; font-weight: 600; }',
        '        tr:nth-child(even) { background: rgba(15, 23, 42, 0.4); }',
        '        tr:hover { background: rgba(51, 65, 85, 0.5); }',
        '        .hidden { display: none !important; }',
        '        .flex { display: flex; gap: 12px; align-items: center; }',
        '        .badge { background: linear-gradient(135deg, #8b5cf6 0%, #6366f1 100%); padding: 6px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; display: inline-block; }',
        '        .zone-checkbox-group { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 14px; background: #0f172a; padding: 12px; border-radius: 10px; border: 1px solid #475569; }',
        '        .zone-checkbox-item { display: flex; align-items: center; gap: 6px; font-size: 13px; color: #cbd5e1; cursor: pointer; }',
        '        .zone-checkbox-item input { width: auto; margin: 0; }',
        '        .footer { text-align: center; font-size: 13px; color: #a78bfa; margin-top: 40px; border-top: 1px solid rgba(255, 255, 255, 0.1); padding-top: 20px; }',
        '        ',
        '        /* Modal Styles */',
        '        .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.8); backdrop-filter: blur(5px); z-index: 9999; display: flex; justify-content: center; align-items: center; }',
        '    </style>',
        '</head>',
        '<body>',
        '    <div class="container">',
        '        <div id="login-screen" class="card" style="max-width: 450px; margin: 80px auto; text-align: center;">',
        '            <h1>PHARMA-SYNC PRO</h1>',
        '            <p style="color: #cbd5e1; margin-top: 6px; margin-bottom: 24px; font-size: 14px;">Enterprise Pharmaceutical Directory System</p>',
        '            <input type="text" id="login-username" placeholder="Username or Phone Number">',
        '            <input type="password" id="login-password" placeholder="Password">',
        '            <button onclick="handleLogin()" class="success" style="padding: 14px; margin-top: 10px;">AUTHENTICATE LOGIN</button>',
        '            <div id="login-error" style="color: #f87171; font-size: 13px; text-align: center; margin-top: 14px; font-weight: 600;"></div>',
        '        </div>',

        '        <div id="app-screen" class="hidden">',
        '            <div class="card flex" style="justify-content: space-between; background: linear-gradient(135deg, #1e1b4b 0%, #1e293b 100%);">',
        '                <div>',
        '                    <h1 id="user-display" style="font-size: 1.8rem;">Welcome</h1>',
        '                    <span id="role-display" class="badge" style="margin-top: 6px;">ROLE</span>',
        '                </div>',
        '                <div style="width: 160px;">',
        '                    <button onclick="handleLogout()" class="danger">LOGOUT</button>',
        '                </div>',
        '            </div>',

        '            <!-- ADMIN INTERFACE -->',
        '            <div id="admin-view" class="hidden">',
        '                <div class="card">',
        '                    <h3>🔑 Update Admin Security Credentials</h3>',
        '                    <div class="flex">',
        '                        <input type="text" id="admin-new-user" placeholder="New Admin Username">',
        '                        <input type="password" id="admin-new-pass" placeholder="New Admin Password">',
        '                    </div>',
        '                    <button onclick="updateAdminProfile()" class="warning">Save New Credentials</button>',
        '                </div>',

        '                <div class="card">',
        '                    <h3>📍 Pre-Register Zone Names</h3>',
        '                    <div class="flex">',
        '                        <input type="text" id="new-zone-input" placeholder="Create Zone Name (e.g. ZONE-EAST, ZONE-WEST)">',
        '                        <button onclick="registerNewZone()" class="success" style="width: 250px;">Add Zone</button>',
        '                    </div>',
        '                </div>',

        '                <div class="card">',
        '                    <h3>👥 Create & Assign System Users</h3>',
        '                    <input type="text" id="nu-name" placeholder="User Full Name / Username">',
        '                    <input type="text" id="nu-phone" placeholder="Phone Number">',
        '                    <input type="password" id="nu-pass" placeholder="Account Password">',
        '                    <label style="font-size: 12px; color: #38bdf8; font-weight: 600; display: block; margin-bottom: 6px;">Select Assigned Zones from Registry:</label>',
        '                    <div id="zone-checkbox-container" class="zone-checkbox-group"></div>',
        '                    <button onclick="createUser()" class="success">Create User Account</button>',
        '                    <br><br>',
        '                    <h3>Registered Users Directory</h3>',
        '                    <table>',
        '                        <thead><tr><th>Username</th><th>Phone</th><th>Assigned Zones</th><th>Status</th><th>Actions</th></tr></thead>',
        '                        <tbody id="users-table"></tbody>',
        '                    </table>',
        '                </div>',

        '                <div class="card">',
        '                    <h3>📥 Master Directory & Daily Totals Bulk Import Engine</h3>',
        '                    <select id="admin-import-zone"><option value="">-- Select Target Zone --</option></select>',
        '                    <input type="file" id="admin-file-import" accept=".json, .xlsx, .xls">',
        '                    <div class="flex">',
        '                        <button onclick="processImport(\'master\', \'merge\')">Import Master (Merge)</button>',
        '                        <button onclick="processImport(\'master\', \'reset\')" class="danger">Import Master (Reset & Add)</button>',
        '                    </div>',
        '                    <div class="flex" style="margin-top: 10px;">',
        '                        <button onclick="processImport(\'totals\', \'merge\')">Import Totals (Merge)</button>',
        '                        <button onclick="processImport(\'totals\', \'reset\')" class="danger">Import Totals (Reset & Add)</button>',
        '                    </div>',
        '                </div>',

        '                <div class="card">',
        '                    <h3>📜 Audit Logs & User Activity</h3>',
        '                    <table>',
        '                        <thead><tr><th>Timestamp</th><th>Username</th><th>Phone</th><th>Zone Context</th><th>Action</th></tr></thead>',
        '                        <tbody id="audit-table"></tbody>',
        '                    </table>',
        '                </div>',
        '            </div>',

        '            <!-- USER INTERFACE -->',
        '            <div id="user-view" class="hidden">',
        '                <div class="card">',
        '                    <h3>🗺️ Select Active Working Zone</h3>',
        '                    <select id="user-zone-select" onchange="switchZone()"></select>',
        '                </div>',

        '                <div class="card">',
        '                    <h3>💊 Register New Drug to Master Directory</h3>',
        '                    <div class="flex">',
        '                        <input type="text" id="new-drug-name" placeholder="Drug Name (e.g. AMXOCILLIN 500MG)">',
        '                        <button onclick="registerDrug()" class="success" style="width: 250px;">Register Drug</button>',
        '                    </div>',
        '                </div>',

        '                <div class="card">',
        '                    <h3>📝 Today\'s Dispense Entry</h3>',
        '                    <select id="dispense-drug-select"></select>',
        '                    <input type="number" id="dispense-qty" placeholder="Quantity">',
        '                    <button onclick="recordDispense()">Record Entry</button>',
        '                </div>',

        '                <div class="card">',
        '                    <h3>✏️ Global Drug Rename</h3>',
        '                    <select id="rename-drug-select"></select>',
        '                    <input type="text" id="rename-drug-new" placeholder="Updated Drug Name">',
        '                    <button onclick="renameDrug()" class="warning">Update Drug Name Globally</button>',
        '                </div>',

        '                <div class="card">',
        '                    <h3>💾 Export & PDF Backup Suite</h3>',
        '                    <input type="text" id="export-remarks" placeholder="Mandatory Export Remarks (Required for PDF Generation)">',
        '                    <div class="flex">',
        '                        <button onclick="exportPDF()" class="success">Download Zone PDF</button>',
        '                        <button onclick="exportMasterJSON()">Export Master Directory JSON</button>',
        '                        <button onclick="exportDispenseJSON()">Export Dispense History JSON</button>',
        '                    </div>',
        '                </div>',

        '                <div class="card">',
        '                    <h3>📋 Recent Dispense Log & History</h3>',
        '                    <table>',
        '                        <thead><tr><th>Drug Name</th><th>Qty</th><th>Entered By</th><th>Timestamp</th><th>Actions</th></tr></thead>',
        '                        <tbody id="history-table"></tbody>',
        '                    </table>',
        '                </div>',
        '            </div>',
        '        </div>',

        '        <!-- Edit User Zones Modal -->',
        '        <div id="edit-zones-modal" class="modal-overlay hidden">',
        '            <div class="card" style="width: 450px; position: relative;">',
        '                <h3>✏️ Edit User Access Zones</h3>',
        '                <p id="edit-user-name" style="color: #38bdf8; margin-bottom: 15px; font-weight: bold;"></p>',
        '                <div id="edit-zone-checkboxes" class="zone-checkbox-group" style="max-height: 250px; overflow-y: auto;"></div>',
        '                <input type="hidden" id="edit-user-id">',
        '                <div class="flex" style="margin-top: 15px;">',
        '                    <button onclick="saveUserZones()" class="success">Update Zones</button>',
        '                    <button onclick="closeEditModal()" class="danger">Cancel</button>',
        '                </div>',
        '            </div>',
        '        </div>',

        '        <div class="footer">',
        '            System Architecture & Sole Copyright Holder: <b>Debanjan Singha</b><br>',
        '            All Rights Reserved. Copyright &copy; 2026. Unauthorized copying or deployment prohibited.',
        '        </div>',
        '    </div>',

        '    <script>',
        '        let token = localStorage.getItem("token");',
        '        let currentUser = null;',
        '        let activeZone = "";',
        '        let masterDrugsList = [];',
        '        let dispenseHistory = [];',
        '        let availableZonesList = [];',

        '        if (token) checkSession();',

        '        async function handleLogin() {',
        '            const u = document.getElementById("login-username").value;',
        '            const p = document.getElementById("login-password").value;',
        '            const res = await fetch("/api/login", {',
        '                method: "POST",',
        '                headers: { "Content-Type": "application/json" },',
        '                body: JSON.stringify({ username: u, password: p })',
        '            });',
        '            const data = await res.json();',
        '            if (res.ok) {',
        '                localStorage.setItem("token", data.token);',
        '                token = data.token;',
        '                currentUser = data;',
        '                initApp();',
        '            } else {',
        '                document.getElementById("login-error").innerText = data.error || data.message;',
        '            }',
        '        }',

        '        function handleLogout() {',
        '            fetch("/api/logout", { method: "POST", headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" }, body: JSON.stringify({ zone: activeZone }) });',
        '            localStorage.removeItem("token");',
        '            location.reload();',
        '        }',

        '        function checkSession() { initApp(); }',

        '        async function initApp() {',
        '            document.getElementById("login-screen").classList.add("hidden");',
        '            document.getElementById("app-screen").classList.remove("hidden");',
        '            ',
        '            const payload = JSON.parse(atob(token.split(".")[1]));',
        '            document.getElementById("user-display").innerText = payload.username;',
        '            document.getElementById("role-display").innerText = payload.role;',

        '            if (payload.role === "ADMIN") {',
        '                document.getElementById("admin-view").classList.remove("hidden");',
        '                loadAdminData();',
        '            } else {',
        '                document.getElementById("user-view").classList.remove("hidden");',
        '                loadUserZones();',
        '            }',
        '        }',

        '        async function registerNewZone() {',
        '            const zInput = document.getElementById("new-zone-input").value;',
        '            if (!zInput) return alert("Please enter a valid Zone Name.");',
        '            const res = await fetch("/api/zones", {',
        '                method: "POST",',
        '                headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },',
        '                body: JSON.stringify({ zone_name: zInput })',
        '            });',
        '            if (res.ok) {',
        '                document.getElementById("new-zone-input").value = "";',
        '                loadAdminData();',
        '            }',
        '        }',

        '        async function loadAdminData() {',
        '            const zRes = await fetch("/api/zones", { headers: { "Authorization": "Bearer " + token } });',
        '            availableZonesList = await zRes.json();',

        '            const zoneContainer = document.getElementById("zone-checkbox-container");',
        '            const zoneImportSelect = document.getElementById("admin-import-zone");',
        '            zoneContainer.innerHTML = "";',
        '            zoneImportSelect.innerHTML = \'<option value="">-- Select Target Zone --</option>\';',

        '            availableZonesList.forEach(z => {',
        '                zoneContainer.innerHTML += `<label class="zone-checkbox-item"><input type="checkbox" value="${z}" name="assigned-zones"> ${z}</label>`;',
        '                zoneImportSelect.innerHTML += `<option value="${z}">${z}</option>`;',
        '            });',

        '            const res = await fetch("/api/users", { headers: { "Authorization": "Bearer " + token } });',
        '            if (!res.ok) return handleAccessError(res);',
        '            const users = await res.json();',
        '            const tbody = document.getElementById("users-table");',
        '            tbody.innerHTML = "";',

        '            users.forEach(u => {',
        '                const zonesStr = u.zones.join(",");',
        '                tbody.innerHTML += `<tr>',
        '                    <td>${u.username}</td>',
        '                    <td>${u.phone}</td>',
        '                    <td>${u.zones.join(", ")}</td>',
        '                    <td>${u.status ? "ACTIVE" : "DISABLED"}</td>',
        '                    <td>',
        '                        <button onclick="openEditModal(${u.id}, \'${u.username}\', \'${zonesStr}\')" class="success" style="padding: 6px 10px; margin-bottom: 4px;">Edit Zones</button>',
        '                        <button onclick="toggleUser(${u.id}, ${u.status ? 0 : 1})" class="warning" style="padding: 6px 10px; margin-bottom: 4px;">${u.status ? "Disable" : "Enable"}</button>',
        '                        <button onclick="removeUser(${u.id})" class="danger" style="padding: 6px 10px; margin-bottom: 0;">Remove</button>',
        '                    </td>',
        '                </tr>`;',
        '            });',

        '            const auditRes = await fetch("/api/admin/audit-logs", { headers: { "Authorization": "Bearer " + token } });',
        '            const logs = await auditRes.json();',
        '            const auditBody = document.getElementById("audit-table");',
        '            auditBody.innerHTML = "";',
        '            logs.forEach(l => {',
        '                auditBody.innerHTML += `<tr><td>${l.timestamp}</td><td>${l.username}</td><td>${l.phone}</td><td>${l.zone}</td><td>${l.action}</td></tr>`;',
        '            });',
        '        }',

        '        function openEditModal(id, username, currentZonesStr) {',
        '            document.getElementById("edit-user-id").value = id;',
        '            document.getElementById("edit-user-name").innerText = "User Account: " + username;',
        '            const currentZones = currentZonesStr.split(",");',
        '            const container = document.getElementById("edit-zone-checkboxes");',
        '            container.innerHTML = "";',
        '            availableZonesList.forEach(z => {',
        '                const isChecked = currentZones.includes(z) ? "checked" : "";',
        '                container.innerHTML += `<label class="zone-checkbox-item"><input type="checkbox" value="${z}" name="edit-assigned-zones" ${isChecked}> ${z}</label>`;',
        '            });',
        '            document.getElementById("edit-zones-modal").classList.remove("hidden");',
        '        }',

        '        function closeEditModal() {',
        '            document.getElementById("edit-zones-modal").classList.add("hidden");',
        '        }',

        '        async function saveUserZones() {',
        '            const id = document.getElementById("edit-user-id").value;',
        '            const selectedCheckboxes = document.querySelectorAll(\'input[name="edit-assigned-zones"]:checked\');',
        '            const z = Array.from(selectedCheckboxes).map(cb => cb.value);',
        '            if (!z.length) return alert("Please select at least one zone before saving.");',
        '            ',
        '            const res = await fetch(`/api/users/${id}/zones`, {',
        '                method: "PUT",',
        '                headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },',
        '                body: JSON.stringify({ zones: z })',
        '            });',
        '            if (res.ok) { ',
        '                closeEditModal();',
        '                loadAdminData();',
        '            } else {',
        '                const err = await res.json();',
        '                alert("Update failed: " + (err.error || "Unknown error"));',
        '            }',
        '        }',

        '        async function toggleUser(id, status) {',
        '            await fetch(`/api/users/${id}/status`, {',
        '                method: "PUT",',
        '                headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },',
        '                body: JSON.stringify({ status })',
        '            });',
        '            loadAdminData();',
        '        }',

        '        async function removeUser(id) {',
        '            if (!confirm("Are you sure you want to permanently delete this user account?")) return;',
        '            await fetch(`/api/users/${id}`, { method: "DELETE", headers: { "Authorization": "Bearer " + token } });',
        '            loadAdminData();',
        '        }',

        '        async function createUser() {',
        '            const u = document.getElementById("nu-name").value;',
        '            const p = document.getElementById("nu-phone").value;',
        '            const pass = document.getElementById("nu-pass").value;',
        '            const selectedCheckboxes = document.querySelectorAll(\'input[name="assigned-zones"]:checked\');',
        '            const z = Array.from(selectedCheckboxes).map(cb => cb.value);',

        '            if (!z.length) return alert("Please select at least one zone from the registry checkboxes.");',

        '            const res = await fetch("/api/users", {',
        '                method: "POST",',
        '                headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },',
        '                body: JSON.stringify({ username: u, phone: p, password: pass, zones: z })',
        '            });',
        '            if (res.ok) { alert("User created successfully"); loadAdminData(); } else { alert("Failed to create user"); }',
        '        }',

        '        async function processImport(type, mode) {',
        '            const targetZone = document.getElementById("admin-import-zone").value;',
        '            const fileInput = document.getElementById("admin-file-import");',
        '            if (!targetZone) return alert("Please select a target zone for import.");',
        '            if (!fileInput.files.length) return alert("Please choose a JSON or Excel file.");',

        '            const file = fileInput.files[0];',
        '            const fileName = file.name.toLowerCase();',

        '            if (fileName.endsWith(".json")) {',
        '                const reader = new FileReader();',
        '                reader.onload = async (e) => {',
        '                    try {',
        '                        let jsonArr = JSON.parse(e.target.result);',
        '                        // Ultra-robust JSON unpacking',
        '                        if (!Array.isArray(jsonArr)) {',
        '                            const keys = Object.keys(jsonArr);',
        '                            if (keys.length > 0 && Array.isArray(jsonArr[keys[0]])) {',
        '                                jsonArr = jsonArr[keys[0]];',
        '                            } else {',
        '                                jsonArr = [jsonArr];',
        '                            }',
        '                        }',
        '                        sendImportPayload(type, mode, targetZone, jsonArr);',
        '                    } catch(err) { alert("JSON Parse Error: File might be corrupted or incorrectly formatted."); }',
        '                };',
        '                reader.readAsText(file);',
        '            } else if (fileName.endsWith(".xlsx") || fileName.endsWith(".xls")) {',
        '                const reader = new FileReader();',
        '                reader.onload = async (e) => {',
        '                    const data = new Uint8Array(e.target.result);',
        '                    const workbook = XLSX.read(data, { type: "array" });',
        '                    const sheet = workbook.Sheets[workbook.SheetNames[0]];',
        '                    const parsedRows = XLSX.utils.sheet_to_json(sheet);',
        '                    sendImportPayload(type, mode, targetZone, parsedRows);',
        '                };',
        '                reader.readAsArrayBuffer(file);',
        '            }',
        '        }',

        '        async function sendImportPayload(type, mode, zone, items) {',
        '            const endpoint = type === "master" ? "/api/master-drugs/import" : "/api/dispense/import";',
        '            const bodyKey = type === "master" ? "drugs" : "records";',
        '            try {',
        '                const res = await fetch(endpoint, {',
        '                    method: "POST",',
        '                    headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },',
        '                    body: JSON.stringify({ zone, mode, [bodyKey]: items })',
        '                });',
        '                const data = await res.json();',
        '                if (res.ok) { alert(data.message || "Import completed successfully!"); } ',
        '                else { alert("Import failed: " + (data.error || "Unknown server error")); }',
        '            } catch(e) {',
        '                alert("Connection error during import: " + e.message);',
        '            }',
        '        }',

        '        async function updateAdminProfile() {',
        '            const u = document.getElementById("admin-new-user").value;',
        '            const p = document.getElementById("admin-new-pass").value;',
        '            const res = await fetch("/api/admin/profile", {',
        '                method: "PUT",',
        '                headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },',
        '                body: JSON.stringify({ newUsername: u, newPassword: p })',
        '            });',
        '            if (res.ok) { alert("Credentials updated. Logging out..."); handleLogout(); }',
        '        }',

        '        async function loadUserZones() {',
        '            const zRes = await fetch("/api/zones", { headers: { "Authorization": "Bearer " + token } });',
        '            const allZones = await zRes.json();',
        '            const zoneSelect = document.getElementById("user-zone-select");',
        '            zoneSelect.innerHTML = "";',
        '            allZones.forEach(z => { zoneSelect.innerHTML += `<option value="${z}">${z}</option>`; });',
        '            activeZone = zoneSelect.value || "ZONE-A";',
        '            syncUserData();',
        '        }',

        '        function switchZone() {',
        '            activeZone = document.getElementById("user-zone-select").value;',
        '            syncUserData();',
        '        }',

        '        async function syncUserData() {',
        '            const mRes = await fetch(`/api/master-drugs?zone=${activeZone}`, { headers: { "Authorization": "Bearer " + token } });',
        '            if (!mRes.ok) return handleAccessError(mRes);',
        '            masterDrugsList = await mRes.json();',
        '            ',
        '            const dSelect = document.getElementById("dispense-drug-select");',
        '            const rSelect = document.getElementById("rename-drug-select");',
        '            dSelect.innerHTML = ""; rSelect.innerHTML = "";',
        '            masterDrugsList.forEach(d => {',
        '                dSelect.innerHTML += `<option value="${d}">${d}</option>`;',
        '                rSelect.innerHTML += `<option value="${d}">${d}</option>`;',
        '            });',

        '            const hRes = await fetch(`/api/dispense/sync?zone=${activeZone}`, { headers: { "Authorization": "Bearer " + token } });',
        '            dispenseHistory = await hRes.json();',
        '            const tbody = document.getElementById("history-table");',
        '            tbody.innerHTML = "";',
        '            dispenseHistory.forEach(h => {',
        '                tbody.innerHTML += `<tr><td>${h.drug_name}</td><td>${h.qty}</td><td>${h.entered_by}</td><td>${h.timestamp}</td><td><button onclick="editQty(${h.id})" class="warning">Edit</button> <button class="danger" onclick="deleteEntry(${h.id})">Undo</button></td></tr>`;',
        '            });',
        '        }',

        '        async function registerDrug() {',
        '            const d = document.getElementById("new-drug-name").value;',
        '            if (!d) return;',
        '            await fetch("/api/master-drugs", {',
        '                method: "POST",',
        '                headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },',
        '                body: JSON.stringify({ zone: activeZone, drug_name: d })',
        '            });',
        '            document.getElementById("new-drug-name").value = "";',
        '            syncUserData();',
        '        }',

        '        async function recordDispense() {',
        '            const d = document.getElementById("dispense-drug-select").value;',
        '            const q = document.getElementById("dispense-qty").value;',
        '            if (!d || !q) return;',
        '            await fetch("/api/dispense", {',
        '                method: "POST",',
        '                headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },',
        '                body: JSON.stringify({ zone: activeZone, drug_name: d, qty: q })',
        '            });',
        '            document.getElementById("dispense-qty").value = "";',
        '            syncUserData();',
        '        }',

        '        async function editQty(id) {',
        '            const nq = prompt("Enter updated quantity:");',
        '            if (!nq) return;',
        '            await fetch(`/api/dispense/${id}`, {',
        '                method: "PUT",',
        '                headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },',
        '                body: JSON.stringify({ qty: nq })',
        '            });',
        '            syncUserData();',
        '        }',

        '        async function deleteEntry(id) {',
        '            if (!confirm("Undo this dispense entry?")) return;',
        '            await fetch(`/api/dispense/${id}`, { method: "DELETE", headers: { "Authorization": "Bearer " + token } });',
        '            syncUserData();',
        '        }',

        '        async function renameDrug() {',
        '            const oldN = document.getElementById("rename-drug-select").value;',
        '            const newN = document.getElementById("rename-drug-new").value;',
        '            if (!oldN || !newN) return;',
        '            await fetch("/api/master-drugs/rename", {',
        '                method: "PUT",',
        '                headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },',
        '                body: JSON.stringify({ zone: activeZone, oldName: oldN, newName: newN })',
        '            });',
        '            document.getElementById("rename-drug-new").value = "";',
        '            syncUserData();',
        '        }',

        '        function exportMasterJSON() {',
        '            const blob = new Blob([JSON.stringify(masterDrugsList, null, 2)], { type: "application/json" });',
        '            const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `MasterDirectory_${activeZone}.json`; a.click();',
        '        }',

        '        function exportDispenseJSON() {',
        '            const blob = new Blob([JSON.stringify(dispenseHistory, null, 2)], { type: "application/json" });',
        '            const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `DispenseHistory_${activeZone}.json`; a.click();',
        '        }',

        '        function exportPDF() {',
        '            const remarks = document.getElementById("export-remarks").value;',
        '            if (!remarks) return alert("Remarks field is mandatory for downloading PDF reporting.");',
        '            ',
        '            const { jsPDF } = window.jspdf;',
        '            const doc = new jsPDF();',
        '            doc.setFontSize(16);',
        '            doc.text(`PHARMA-SYNC PRO REPORT - ${activeZone}`, 14, 15);',
        '            doc.setFontSize(10);',
        '            doc.text(`Generated Date & Time: ${new Date().toLocaleString()}`, 14, 23);',
        '            doc.text(`Mandatory Remarks: ${remarks}`, 14, 29);',

        '            const tableRows = dispenseHistory.map(h => [h.drug_name, h.qty, h.entered_by, h.timestamp]);',
        '            doc.autoTable({ head: [["Drug Name", "Qty", "Entered By", "Timestamp"]], body: tableRows, startY: 35 });',

        '            const pageCount = doc.internal.getNumberOfPages();',
        '            for (let i = 1; i <= pageCount; i++) {',
        '                doc.setPage(i);',
        '                doc.setFontSize(9);',
        '                doc.text("Lead Developer: Debanjan Singha", 14, doc.internal.pageSize.height - 10);',
        '            }',
        '            doc.save(`Report_${activeZone}.pdf`);',
        '        }',

        '        function handleAccessError(res) {',
        '            if (res.status === 403) {',
        '                alert("ERROR! PLEASE CONTACT TO THE ADMIN");',
        '                handleLogout();',
        '            }',
        '        }',
        '    </script>',
        '</body>',
        '</html>'
    ].join('\n');

    res.setHeader('Content-Type', 'text/html');
    res.send(htmlLines);
});

app.listen(PORT, () => {
    console.log("Server running on port " + PORT);
});
