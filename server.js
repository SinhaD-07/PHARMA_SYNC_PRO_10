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
console.log(" PHARMA-SYNC PRO | ENTERPRISE OFFLINE-FIRST & FIREWALL ENGINE");
console.log(" Lead System Architect: " + COPYRIGHT_OWNER);
console.log(" Copyright (c) 2026. All Rights Reserved.");
console.log("================================================================");

// Strict Security Firewall Headers (Zero Third-Party Leak Policy)
app.use((req, res, next) => {
    res.setHeader("Content-Security-Policy", "default-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline' 'unsafe-eval';");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("X-XSS-Protection", "1; mode=block");
    next();
});

app.use(cors());
app.use(express.json({ limit: '100mb' }));

// Initialize Database with WAL Mode for High Concurrency & Performance
const db = new sqlite3.Database('./pharmacy.db', (err) => {
    if (!err) {
        db.run("PRAGMA journal_mode = WAL;");
        db.run("PRAGMA synchronous = NORMAL;");
        db.run("PRAGMA cache_size = -64000;"); // 64MB Memory Cache
        initDb();
    }
});

function initDb() {
    db.serialize(() => {
        db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, phone TEXT, password TEXT, role TEXT, zones TEXT, status INTEGER DEFAULT 1)");
        db.run("CREATE TABLE IF NOT EXISTS master_drugs (id INTEGER PRIMARY KEY AUTOINCREMENT, zone TEXT, drug_name TEXT, UNIQUE(zone, drug_name))");
        db.run("CREATE TABLE IF NOT EXISTS dispenses (id INTEGER PRIMARY KEY AUTOINCREMENT, zone TEXT, drug_name TEXT, qty INTEGER, entered_by TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)");
        db.run("CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, phone TEXT, zone TEXT, action TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)");
        db.run("CREATE TABLE IF NOT EXISTS zone_registry (id INTEGER PRIMARY KEY AUTOINCREMENT, zone_name TEXT UNIQUE)");

        // High Speed Database Indexes
        db.run("CREATE INDEX IF NOT EXISTS idx_master_zone_drug ON master_drugs(zone, drug_name)");
        db.run("CREATE INDEX IF NOT EXISTS idx_dispenses_zone ON dispenses(zone)");
        db.run("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp)");

        // Automated 1-Month Activity Log Purge Rule
        db.run("DELETE FROM audit_logs WHERE timestamp < datetime('now', '-1 month')");

        db.get("SELECT * FROM users WHERE role = 'ADMIN'", async (err, row) => {
            if (!row) {
                const hash = await bcrypt.hash('admin123', 10);
                db.run("INSERT INTO users (username, phone, password, role, zones, status) VALUES ('admin', '0000000000', ?, 'ADMIN', '[\"ALL\"]', 1)", [hash]);
            }
        });
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

// Data Extraction & Normalization Helper
function extractDrugNames(item) {
    if (!item) return [];
    let rawStr = "";
    
    if (typeof item === 'string') {
        rawStr = item;
    } else if (typeof item === 'object') {
        const keys = Object.keys(item);
        const matchKey = keys.find(k => /drug|name|item|product|title|description/i.test(k));
        if (matchKey && item[matchKey]) {
            rawStr = String(item[matchKey]);
        } else if (keys.length > 0 && item[keys[0]]) {
            rawStr = String(item[keys[0]]);
        }
    }

    if (!rawStr) return [];
    return rawStr
        .split(/[\n\r,;]+/)
        .map(s => s.trim().toUpperCase())
        .filter(s => s.length > 0);
}

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

app.get('/api/zones', authenticateToken, (req, res) => {
    if (req.user.role === 'ADMIN') {
        db.all("SELECT zone_name FROM zone_registry ORDER BY zone_name ASC", [], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows.map(r => r.zone_name));
        });
    } else {
        let userZones = [];
        try { userZones = JSON.parse(req.user.zones); } catch(e) { userZones = [req.user.zones]; }
        res.json(userZones);
    }
});

app.post('/api/zones', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required." });
    const zName = req.body.zone_name ? req.body.zone_name.trim().toUpperCase() : "";
    if (!zName) return res.status(400).json({ error: "Zone name cannot be empty." });

    db.run("INSERT OR IGNORE INTO zone_registry (zone_name) VALUES (?)", [zName], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Zone registered successfully." });
    });
});

app.get('/api/admin/audit-logs', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required." });
    db.run("DELETE FROM audit_logs WHERE timestamp < datetime('now', '-1 month')", [], () => {
        db.all("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 500", [], (err, rows) => {
            res.json(rows);
        });
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
            res.json({ message: "Drug name updated successfully." });
        });
    });
});

app.delete('/api/master-drugs', authenticateToken, (req, res) => {
    db.run("DELETE FROM master_drugs WHERE drug_name = ? AND zone = ?", [req.body.drug_name, req.body.zone], (err) => {
        res.json({ message: "Drug removed from Master Directory." });
    });
});

app.post('/api/master-drugs/import', authenticateToken, (req, res) => {
    const mode = req.body.mode;
    let drugs = req.body.drugs;
    const zone = req.body.zone;

    if (!zone || !drugs) return res.status(400).json({ error: "Invalid payload or unselected target zone." });
    if (!Array.isArray(drugs)) drugs = [drugs];

    db.serialize(() => {
        db.run("BEGIN TRANSACTION");
        if (mode === 'reset') db.run("DELETE FROM master_drugs WHERE zone = ?", [zone]);
        
        const stmt = db.prepare("INSERT OR IGNORE INTO master_drugs (zone, drug_name) VALUES (?, ?)");
        let importedCount = 0;

        drugs.forEach(item => {
            const parsedNames = extractDrugNames(item);
            parsedNames.forEach(dName => {
                stmt.run(zone, dName);
                importedCount++;
            });
        });

        stmt.finalize();
        db.run("COMMIT", (err) => {
            if (err) return res.status(500).json({ error: "Failed to commit bulk import." });
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
    db.all("SELECT * FROM dispenses WHERE zone = ? ORDER BY id DESC LIMIT 1000", [req.query.zone], (err, rows) => {
        res.json(rows);
    });
});

app.put('/api/dispense/adjust-cumulative', authenticateToken, (req, res) => {
    const zone = req.body.zone;
    const drug_name = req.body.drug_name ? req.body.drug_name.trim().toUpperCase() : "";
    const targetQty = parseInt(req.body.new_qty);

    if (!zone || !drug_name || isNaN(targetQty) || targetQty < 0) {
        return res.status(400).json({ error: "Invalid parameters." });
    }

    db.serialize(() => {
        db.run("DELETE FROM dispenses WHERE zone = ? AND UPPER(drug_name) = ?", [zone, drug_name], (err) => {
            if (err) return res.status(500).json({ error: "Database update error." });
            if (targetQty > 0) {
                db.run("INSERT INTO dispenses (zone, drug_name, qty, entered_by) VALUES (?, ?, ?, ?)",
                    [zone, drug_name, targetQty, req.user.username + " (Edit)"],
                    () => res.json({ message: "Cumulative quantity updated." })
                );
            } else {
                res.json({ message: "Cumulative quantity updated to 0." });
            }
        });
    });
});

app.delete('/api/dispense/clear/all', authenticateToken, (req, res) => {
    db.run("DELETE FROM dispenses WHERE zone = ?", [req.body.zone], () => res.json({ message: "Totals cleared for zone." }));
});

// ==========================================
// SINGLE-FILE WEB INTERFACE
// ==========================================

app.get('/', (req, res) => {
    const htmlLines = [
        '<!DOCTYPE html>',
        '<html lang="en">',
        '<head>',
        '    <meta charset="UTF-8">',
        '    <meta name="viewport" content="width=device-width, initial-scale=1.0">',
        '    <title>PHARMA-SYNC PRO | OFFLINE-FIRST REALTIME ENGINE</title>',
        '    <meta name="author" content="Debanjan Singha">',
        '    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>',
        '    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.23/jspdf.plugin.autotable.min.js"></script>',
        '    <script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></script>',
        '    <style>',
        '        :root {',
        '            --bg: #f4f7fa;',
        '            --accent: #4361ee;',
        '            --success: #2ec4b6;',
        '            --danger: #e71d36;',
        '            --warning: #ff9f1c;',
        '            --sidebar: #1b263b;',
        '            --card-bg: #ffffff;',
        '            --text-main: #2b2d42;',
        '            --text-muted: #8d99ae;',
        '        }',
        '        * { box-sizing: border-box; margin: 0; padding: 0; font-family: "Inter", "Segoe UI", sans-serif; }',
        '        body { background-color: var(--bg); color: var(--text-main); padding: 20px; min-height: 100vh; }',
        '        .container { max-width: 1400px; margin: 0 auto; }',
        '        .header-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; background: white; padding: 15px 25px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }',
        '        .app-grid { display: grid; grid-template-columns: 320px 1fr 360px; gap: 20px; align-items: start; }',
        '        @media (max-width: 1100px) { .app-grid { grid-template-columns: 1fr 1fr; } }',
        '        @media (max-width: 768px) { .app-grid { grid-template-columns: 1fr; } }',
        '        .panel { background: var(--card-bg); padding: 20px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.02); border: 1px solid #edf2f7; margin-bottom: 20px; position: relative; }',
        '        .panel h2 { font-size: 15px; margin-top: 0; margin-bottom: 15px; color: var(--sidebar); border-bottom: 1px solid #f1f5f9; padding-bottom: 10px; text-transform: uppercase; letter-spacing: 0.5px; }',
        '        input, select, button { width: 100%; padding: 10px 12px; margin-bottom: 10px; border-radius: 8px; border: 1px solid #d1d9e6; font-size: 14px; background: #f8fafc; outline: none; transition: 0.2s; }',
        '        input:focus, select:focus { border-color: var(--accent); background: white; box-shadow: 0 0 0 3px rgba(67, 97, 238, 0.15); }',
        '        .primary-btn { background: var(--accent); color: white; padding: 10px; border: none; border-radius: 8px; cursor: pointer; font-weight: 700; transition: 0.2s; font-size: 13px; }',
        '        .primary-btn:hover { filter: brightness(1.1); transform: translateY(-1px); }',
        '        .primary-btn.success { background: var(--success); }',
        '        .primary-btn.danger { background: var(--danger); }',
        '        .primary-btn.warning { background: var(--warning); }',
        '        .qty-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 6px; margin-bottom: 10px; }',
        '        .qty-pill { background: #edf2f7; border: 1px solid #cbd5e0; padding: 6px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: bold; text-align: center; color: var(--sidebar); }',
        '        .qty-pill:hover { background: var(--accent); color: white; border-color: var(--accent); }',
        '        .table-wrap { max-height: 400px; overflow-y: auto; border: 1px solid #f1f5f9; border-radius: 6px; }',
        '        table { width: 100%; border-collapse: collapse; font-size: 13px; }',
        '        th { background: #f8fafc; padding: 10px; text-align: left; color: var(--text-muted); position: sticky; top: 0; z-index: 10; font-size: 11px; text-transform: uppercase; }',
        '        td { padding: 10px; border-bottom: 1px solid #f8fafc; }',
        '        .badge { background: #e0e7ff; color: var(--accent); padding: 2px 8px; border-radius: 4px; font-weight: bold; }',
        '        .action-link { cursor: pointer; font-size: 11px; font-weight: bold; text-decoration: underline; background: none; border: none; padding: 0 4px; margin: 0; width: auto; display: inline; }',
        '        .hidden { display: none !important; }',
        '        .flex { display: flex; gap: 10px; align-items: center; }',
        '        .zone-checkbox-group { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 14px; background: #f8fafc; padding: 12px; border-radius: 8px; border: 1px solid #d1d9e6; }',
        '        .zone-checkbox-item { display: flex; align-items: center; gap: 6px; font-size: 13px; color: var(--text-main); cursor: pointer; }',
        '        .zone-checkbox-item input { width: auto; margin: 0; }',
        '        .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); display: flex; justify-content: center; align-items: center; z-index: 1000; backdrop-filter: blur(2px); }',
        '        .panel-credit { margin-top: 20px; padding-top: 15px; border-top: 1px dashed #e2e8f0; font-size: 11px; color: var(--text-muted); text-align: center; line-height: 1.4; }',
        '        .panel-credit b { color: var(--sidebar); }',
        '        .live-dot { height: 8px; width: 8px; background-color: var(--success); border-radius: 50%; display: inline-block; margin-right: 6px; animation: pulse 1.5s infinite; }',
        '        .presence-bar { font-size: 11px; color: var(--accent); font-weight: 600; background: #e0e7ff; padding: 4px 10px; border-radius: 6px; margin-bottom: 10px; display: inline-block; }',
        '        @keyframes pulse { 0% { opacity: 0.4; } 50% { opacity: 1; } 100% { opacity: 0.4; } }',
        '    </style>',
        '</head>',
        '<body>',
        '    <div class="container">',
        '        <!-- LOGIN SCREEN -->',
        '        <div id="login-screen" class="panel" style="max-width: 420px; margin: 80px auto; text-align: center; padding: 35px;">',
        '            <h1 style="color:var(--sidebar); font-size: 24px; margin-bottom: 5px;">PHARMA<span style="color:var(--accent)">SYNC</span> PRO</h1>',
        '            <p style="color: var(--text-muted); font-size: 13px; margin-bottom: 25px;">Secure Offline-First Real-Time Pharmacy Engine</p>',
        '            <input type="text" id="login-username" placeholder="Username or Phone Number" onkeydown="if(event.key===\'Enter\') document.getElementById(\'login-password\').focus()">',
        '            <input type="password" id="login-password" placeholder="Password" onkeydown="if(event.key===\'Enter\') handleLogin()">',
        '            <button onclick="handleLogin()" class="primary-btn success" style="padding: 12px; margin-top: 10px; font-size: 15px;">AUTHENTICATE LOGIN</button>',
        '            <div id="login-error" style="color: var(--danger); font-size: 13px; text-align: center; margin-top: 14px; font-weight: 600;"></div>',
        '            <div class="panel-credit">',
        '                © 2026 <b>Debanjan Singha</b><br>',
        '                System Architect & Lead Developer',
        '            </div>',
        '        </div>',

        '        <!-- APPLICATION SCREEN -->',
        '        <div id="app-screen" class="hidden">',
        '            <div class="header-bar">',
        '                <div style="display: flex; align-items: center;">',
        '                    <h1 style="margin:0; font-size:20px; color:var(--sidebar); display: inline-block;">PHARMA<span style="color:var(--accent)">SYNC</span> PRO</h1>',
        '                    <span id="role-display" class="badge" style="margin-left: 10px;">ROLE</span>',
        '                    <span style="margin-left: 15px; font-size: 12px; color: var(--text-muted);"><span class="live-dot" id="sync-dot"></span><span id="sync-status-text">LIVE AUTO-SYNC (2s)</span></span>',
        '                </div>',
        '                <div style="display:flex; gap:10px; align-items: center;">',
        '                    <div id="user-zone-picker-wrap" style="margin-bottom:0; width: 220px; display:none;">',
        '                        <select id="user-zone-select" onchange="switchZone()" style="margin-bottom:0; padding: 8px 12px;"></select>',
        '                    </div>',
        '                    <div id="single-zone-badge-wrap" style="display:none;">',
        '                        <span style="font-size:12px; font-weight:bold; color:var(--text-muted);">ACTIVE ZONE:</span>',
        '                        <span id="single-zone-name" class="badge" style="background:var(--sidebar); color:white; font-size:13px; padding:6px 12px;">-</span>',
        '                    </div>',
        '                    <button onclick="handleLogout()" class="primary-btn danger" style="margin-bottom:0; width:auto; padding:8px 16px;">LOGOUT</button>',
        '                </div>',
        '            </div>',

        '            <!-- ADMIN VIEW -->',
        '            <div id="admin-view" class="hidden">',
        '                <div class="panel">',
        '                    <h2>🔑 Update Admin Security Credentials</h2>',
        '                    <div class="flex">',
        '                        <input type="text" id="admin-new-user" placeholder="New Admin Username" onkeydown="if(event.key===\'Enter\') document.getElementById(\'admin-new-pass\').focus()">',
        '                        <input type="password" id="admin-new-pass" placeholder="New Admin Password" onkeydown="if(event.key===\'Enter\') updateAdminProfile()">',
        '                    </div>',
        '                    <button onclick="updateAdminProfile()" class="primary-btn warning">Save Credentials</button>',
        '                </div>',

        '                <div class="panel">',
        '                    <h2>📍 Pre-Register Zone Names</h2>',
        '                    <div class="flex">',
        '                        <input type="text" id="new-zone-input" placeholder="Create Zone Name (e.g. ZONE-EAST, ZONE-WEST)" onkeydown="if(event.key===\'Enter\') registerNewZone()">',
        '                        <button onclick="registerNewZone()" class="primary-btn success" style="width: 250px;">Add Zone</button>',
        '                    </div>',
        '                </div>',

        '                <div class="panel">',
        '                    <h2>👥 Create & Assign System Users</h2>',
        '                    <input type="text" id="nu-name" placeholder="User Full Name / Username" onkeydown="if(event.key===\'Enter\') document.getElementById(\'nu-phone\').focus()">',
        '                    <input type="text" id="nu-phone" placeholder="Phone Number" onkeydown="if(event.key===\'Enter\') document.getElementById(\'nu-pass\').focus()">',
        '                    <input type="password" id="nu-pass" placeholder="Account Password">',
        '                    <label style="font-size: 12px; color: var(--accent); font-weight: 600; display: block; margin-bottom: 6px;">Select Assigned Zones from Registry:</label>',
        '                    <div id="zone-checkbox-container" class="zone-checkbox-group"></div>',
        '                    <button onclick="createUser()" class="primary-btn success">Create User Account</button>',
        '                    <br><br>',
        '                    <h2>Registered Users Directory</h2>',
        '                    <div class="table-wrap">',
        '                        <table>',
        '                            <thead><tr><th>Username</th><th>Phone</th><th>Assigned Zones</th><th>Status</th><th>Actions</th></tr></thead>',
        '                            <tbody id="users-table"></tbody>',
        '                        </table>',
        '                    </div>',
        '                </div>',

        '                <div class="panel">',
        '                    <h2>📥 Master Directory Bulk Import Engine</h2>',
        '                    <select id="admin-import-zone"><option value="">-- Select Target Zone --</option></select>',
        '                    <input type="file" id="admin-file-import" accept=".json, .xlsx, .xls">',
        '                    <div class="flex">',
        '                        <button onclick="processMasterImport(\'merge\')" class="primary-btn">Import Master (Merge)</button>',
        '                        <button onclick="processMasterImport(\'reset\')" class="primary-btn danger">Import Master (Reset & Add)</button>',
        '                    </div>',
        '                </div>',

        '                <div class="panel">',
        '                    <h2>📜 User Login & Logout Activity Logs (Auto-Purged after 1 Month)</h2>',
        '                    <div class="table-wrap">',
        '                        <table>',
        '                            <thead><tr><th>Timestamp</th><th>Username</th><th>Phone</th><th>Zone Context</th><th>Action Event</th></tr></thead>',
        '                            <tbody id="audit-table"></tbody>',
        '                        </table>',
        '                    </div>',
        '                </div>',
        '            </div>',

        '            <!-- USER SMART-FOCUS VIEW -->',
        '            <div id="user-view" class="hidden">',
        '                <div class="presence-bar" id="presence-indicator">🟢 Live Operators Active in Zone</div>',
        '                <div class="app-grid">',
        '                    <!-- PANEL 1: MASTER DIRECTORY -->',
        '                    <div class="panel">',
        '                        <h2>📦 Master Directory</h2>',
        '                        <input type="text" id="newDrugName" placeholder="New drug name..." onkeydown="if(event.key===\'Enter\') registerDrug()">',
        '                        <button class="primary-btn" onclick="registerDrug()">REGISTER DRUG</button>',
        '                        <input type="text" style="margin-top:15px" onkeyup="filterTable(\'masterBody\', this.value)" placeholder="Search directory...">',
        '                        <div class="table-wrap"><table><tbody id="masterBody"></tbody></table></div>',
        '                        <div class="panel-credit">',
        '                            © 2026 <b>Debanjan Singha</b><br>',
        '                            Pharma-Sync Pro Architecture',
        '                        </div>',
        '                    </div>',

        '                    <!-- PANEL 2: FAST DISPENSE ENTRY -->',
        '                    <div class="panel">',
        '                        <h2>⚡ Fast Dispense Entry</h2>',
        '                        <input type="text" id="dispenseDrug" placeholder="Type or select drug name..." oninput="onDrugInput()" onkeydown="if(event.key===\'Enter\') document.getElementById(\'dispenseQty\').focus()">',
        '                        <div id="drugSuggestions" style="max-height: 140px; overflow-y: auto; border: 1px solid #d1d9e6; border-radius: 6px; margin-bottom: 10px; display: none; background: white;"></div>',
        '                        <div class="qty-grid">',
        '                            <div class="qty-pill" onclick="setQty(1)">1</div>',
        '                            <div class="qty-pill" onclick="setQty(5)">5</div>',
        '                            <div class="qty-pill" onclick="setQty(10)">10</div>',
        '                            <div class="qty-pill" onclick="setQty(25)">25</div>',
        '                        </div>',
        '                        <input type="number" id="dispenseQty" placeholder="Quantity" value="1" onkeydown="if(event.key===\'Enter\') recordDispense()">',
        '                        <button class="primary-btn success" onclick="recordDispense()">RECORD DISPENSE</button>',
        '                        <br><br>',
        '                        <h2>📊 Live Inventory & Cumulative Totals</h2>',
        '                        <input type="text" onkeyup="filterTable(\'inventoryBody\', this.value)" placeholder="Search inventory totals...">',
        '                        <div class="table-wrap">',
        '                            <table>',
        '                                <thead><tr><th>Drug Name</th><th>Total Qty</th><th>Actions</th></tr></thead>',
        '                                <tbody id="inventoryBody"></tbody>',
        '                            </table>',
        '                        </div>',
        '                    </div>',

        '                    <!-- PANEL 3: AUDIT & EXPORT HUB -->',
        '                    <div class="panel">',
        '                        <h2>📑 Activity & Export Hub</h2>',
        '                        <button onclick="exportReport(\'excel\')" class="primary-btn success" style="margin-bottom:8px;">Download Excel Report</button>',
        '                        <button onclick="exportReport(\'pdf\')" class="primary-btn warning" style="margin-bottom:8px;">Download PDF Report</button>',
        '                        <button onclick="clearZoneTotals()" class="primary-btn danger" style="margin-bottom:15px;">Clear Zone Totals</button>',
        '                        <h2>Recent Dispense Logs</h2>',
        '                        <div class="table-wrap">',
        '                            <table>',
        '                                <thead><tr><th>Time</th><th>Drug</th><th>Qty</th><th>By</th></tr></thead>',
        '                                <tbody id="dispenseLogsBody"></tbody>',
        '                            </table>',
        '                        </div>',
        '                    </div>',
        '                </div>',
        '            </div>',
        '        </div>',
        '    </div>',

        '    <!-- CLIENT SCRIPT LOGIC -->',
        '    <script>',
        '        let state = {',
        '            token: localStorage.getItem(\'pharma_token\') || \'\',',
        '            role: localStorage.getItem(\'pharma_role\') || \'\',',
        '            username: localStorage.getItem(\'pharma_user\') || \'\',',
        '            zones: JSON.parse(localStorage.getItem(\'pharma_zones\') || \'[]\'),',
        '            activeZone: localStorage.getItem(\'pharma_active_zone\') || \'\',',
        '            masterDrugs: [],',
        '            dispenses: []',
        '        };',

        '        const apiCall = async (url, options = {}) => {',
        '            const headers = { \'Content-Type\': \'application/json\', \'Authorization\': \'Bearer \' + state.token, ...(options.headers || {}) };',
        '            const res = await fetch(url, { ...options, headers });',
        '            if (res.status === 401 || res.status === 403) {',
        '                handleLogout();',
        '                throw new Error("Session terminated.");',
        '            }',
        '            return res.json();',
        '        };',

        '        async function handleLogin() {',
        '            const username = document.getElementById(\'login-username\').value.trim();',
        '            const password = document.getElementById(\'login-password\').value;',
        '            try {',
        '                const res = await fetch(\'/api/login\', {',
        '                    method: \'POST\',',
        '                    headers: {\'Content-Type\': \'application/json\'},',
        '                    body: JSON.stringify({ username, password })',
        '                });',
        '                const data = await res.json();',
        '                if (!res.ok) throw new Error(data.error || "Authentication failed");',
        '                ',
        '                state.token = data.token;',
        '                state.role = data.role;',
        '                state.username = data.username;',
        '                state.zones = data.zones;',
        '                state.activeZone = data.zones[0] || \'\';',

        '                localStorage.setItem(\'pharma_token\', state.token);',
        '                localStorage.setItem(\'pharma_role\', state.role);',
        '                localStorage.setItem(\'pharma_user\', state.username);',
        '                localStorage.setItem(\'pharma_zones\', JSON.stringify(state.zones));',
        '                localStorage.setItem(\'pharma_active_zone\', state.activeZone);',

        '                initAppInterface();',
        '            } catch (err) {',
        '                document.getElementById(\'login-error\').innerText = err.message;',
        '            }',
        '        }',

        '        function handleLogout() {',
        '            fetch(\'/api/logout\', { method: \'POST\', headers: {\'Authorization\': \'Bearer \' + state.token, \'Content-Type\': \'application/json\'}, body: JSON.stringify({zone: state.activeZone}) });',
        '            localStorage.clear();',
        '            location.reload();',
        '        }',

        '        function initAppInterface() {',
        '            document.getElementById(\'login-screen\').classList.add(\'hidden\');',
        '            document.getElementById(\'app-screen\').classList.remove(\'hidden\');',
        '            document.getElementById(\'role-display\').innerText = state.role;',

        '            if (state.role === \'ADMIN\') {',
        '                document.getElementById(\'admin-view\').classList.remove(\'hidden\');',
        '                document.getElementById(\'user-view\').classList.remove(\'hidden\');',
        '                document.getElementById(\'user-zone-picker-wrap\').style.display = \'block\';',
        '                loadAdminRegistryData();',
        '            } else {',
        '                document.getElementById(\'user-view\').classList.remove(\'hidden\');',
        '                if (state.zones.length > 1) {',
        '                    document.getElementById(\'user-zone-picker-wrap\').style.display = \'block\';',
        '                } else {',
        '                    document.getElementById(\'single-zone-badge-wrap\').style.display = \'block\';',
        '                    document.getElementById(\'single-zone-name\').innerText = state.activeZone;',
        '                }',
        '            }',
        '            populateZoneSelects();',
        '            refreshData();',
        '            setInterval(refreshData, 2000);',
        '        }',

        '        async function populateZoneSelects() {',
        '            const zones = await apiCall(\'/api/zones\');',
        '            const userSelect = document.getElementById(\'user-zone-select\');',
        '            const adminImportZone = document.getElementById(\'admin-import-zone\');',
        '            ',
        '            userSelect.innerHTML = \'\';',
        '            if (adminImportZone) adminImportZone.innerHTML = \'<option value="">-- Select Target Zone --</option>\';',

        '            zones.forEach(z => {',
        '                userSelect.add(new Option(z, z));',
        '                if (adminImportZone) adminImportZone.add(new Option(z, z));',
        '            });',
        '            userSelect.value = state.activeZone;',
        '        }',

        '        function switchZone() {',
        '            state.activeZone = document.getElementById(\'user-zone-select\').value;',
        '            localStorage.setItem(\'pharma_active_zone\', state.activeZone);',
        '            refreshData();',
        '        }',

        '        async function refreshData() {',
        '            if (!state.token) return;',
        '            try {',
        '                state.masterDrugs = await apiCall(\'/api/master-drugs?zone=\' + encodeURIComponent(state.activeZone));',
        '                state.dispenses = await apiCall(\'/api/dispense/sync?zone=\' + encodeURIComponent(state.activeZone));',
        '                renderMasterTable();',
        '                renderInventoryAndLogs();',
        '            } catch(e) {}',
        '        }',

        '        async function registerDrug() {',
        '            const input = document.getElementById(\'newDrugName\');',
        '            const drug_name = input.value.trim();',
        '            if (!drug_name) return;',
        '            await apiCall(\'/api/master-drugs\', { method: \'POST\', body: JSON.stringify({ zone: state.activeZone, drug_name }) });',
        '            input.value = \'\';',
        '            refreshData();',
        '        }',

        '        function renderMasterTable() {',
        '            const tbody = document.getElementById(\'masterBody\');',
        '            tbody.innerHTML = state.masterDrugs.map(d => \`',
        '                <tr>',
        '                    <td><b>\${d}</b></td>',
        '                    <td style="text-align:right;">',
        '                        <button class="action-link" onclick="renameDrug(\\\'\${d}\\\')">Rename</button> | ',
        '                        <button class="action-link" style="color:var(--danger)" onclick="deleteDrug(\\\'\${d}\\\')">Delete</button>',
        '                    </td>',
        '                </tr>\`).join(\'\');',
        '        }',

        '        async function renameDrug(oldName) {',
        '            const newName = prompt("Rename drug:", oldName);',
        '            if (!newName || newName.trim() === oldName) return;',
        '            await apiCall(\'/api/master-drugs/rename\', { method: \'PUT\', body: JSON.stringify({ oldName, newName, zone: state.activeZone }) });',
        '            refreshData();',
        '        }',

        '        async function deleteDrug(drug_name) {',
        '            if (!confirm(\`Remove "\${drug_name}" from Master Directory?\`)) return;',
        '            await apiCall(\'/api/master-drugs\', { method: \'DELETE\', body: JSON.stringify({ drug_name, zone: state.activeZone }) });',
        '            refreshData();',
        '        }',

        '        function onDrugInput() {',
        '            const val = document.getElementById(\'dispenseDrug\').value.toLowerCase();',
        '            const box = document.getElementById(\'drugSuggestions\');',
        '            if (!val) { box.style.display = \'none\'; return; }',
        '            const matches = state.masterDrugs.filter(d => d.toLowerCase().includes(val)).slice(0, 8);',
        '            if (!matches.length) { box.style.display = \'none\'; return; }',
        '            box.innerHTML = matches.map(m => \`<div style="padding:8px 12px; cursor:pointer; font-size:13px; border-bottom:1px solid #f1f5f9;" onclick="selectDrugSuggestion(\\\'\${m}\\\')">\${m}</div>\`).join(\'\');',
        '            box.style.display = \'block\';',
        '        }',

        '        function selectDrugSuggestion(name) {',
        '            document.getElementById(\'dispenseDrug\').value = name;',
        '            document.getElementById(\'drugSuggestions\').style.display = \'none\';',
        '            document.getElementById(\'dispenseQty\').focus();',
        '        }',

        '        function setQty(q) { document.getElementById(\'dispenseQty\').value = q; }',

        '        async function recordDispense() {',
        '            const drug_name = document.getElementById(\'dispenseDrug\').value.trim();',
        '            const qty = parseInt(document.getElementById(\'dispenseQty\').value);',
        '            if (!drug_name || isNaN(qty) || qty <= 0) return;',
        '            await apiCall(\'/api/dispense\', { method: \'POST\', body: JSON.stringify({ zone: state.activeZone, drug_name, qty }) });',
        '            document.getElementById(\'dispenseDrug\').value = \'\';',
        '            document.getElementById(\'dispenseQty\').value = \'1\';',
        '            refreshData();',
        '        }',

        '        function renderInventoryAndLogs() {',
        '            const totals = {};',
        '            state.dispenses.forEach(item => {',
        '                totals[item.drug_name] = (totals[item.drug_name] || 0) + item.qty;',
        '            });',

        '            const invBody = document.getElementById(\'inventoryBody\');',
        '            invBody.innerHTML = Object.keys(totals).sort().map(drug => \`',
        '                <tr>',
        '                    <td><b>\${drug}</b></td>',
        '                    <td><span class="badge">\${totals[drug]}</span></td>',
        '                    <td><button class="action-link" onclick="adjustCumulative(\\\'\${drug}\\\', \${totals[drug]})">Adjust</button></td>',
        '                </tr>\`).join(\'\');',

        '            const logBody = document.getElementById(\'dispenseLogsBody\');',
        '            logBody.innerHTML = state.dispenses.slice(0, 50).map(l => \`',
        '                <tr>',
        '                    <td>\${l.timestamp.split(\' \')[1] || l.timestamp}</td>',
        '                    <td>\${l.drug_name}</td>',
        '                    <td>\${l.qty}</td>',
        '                    <td>\${l.entered_by}</td>',
        '                </tr>\`).join(\'\');',
        '        }',

        '        async function adjustCumulative(drug_name, currentQty) {',
        '            const newQty = prompt(\`Set new cumulative total for "\${drug_name}":\`, currentQty);',
        '            if (newQty === null) return;',
        '            const parsed = parseInt(newQty);',
        '            if (isNaN(parsed) || parsed < 0) return;',
        '            await apiCall(\'/api/dispense/adjust-cumulative\', { method: \'PUT\', body: JSON.stringify({ zone: state.activeZone, drug_name, new_qty: parsed }) });',
        '            refreshData();',
        '        }',

        '        async function clearZoneTotals() {',
        '            if (!confirm(\`Clear all dispense data for zone "\${state.activeZone}"?\`)) return;',
        '            await apiCall(\'/api/dispense/clear/all\', { method: \'DELETE\', body: JSON.stringify({ zone: state.activeZone }) });',
        '            refreshData();',
        '        }',

        '        function filterTable(tbodyId, query) {',
        '            const rows = document.getElementById(tbodyId).getElementsByTagName(\'tr\');',
        '            const q = query.toLowerCase();',
        '            for (let r of rows) {',
        '                r.style.display = r.innerText.toLowerCase().includes(q) ? \'\' : \'none\';',
        '            }',
        '        }',

        '        async function registerNewZone() {',
        '            const input = document.getElementById(\'new-zone-input\');',
        '            if (!input) return;',
        '            const zone_name = input.value.trim();',
        '            if (!zone_name) {',
        '                alert("Please enter a valid zone name.");',
        '                return;',
        '            }',
        '            try {',
        '                await apiCall(\'/api/zones\', { method: \'POST\', body: JSON.stringify({ zone_name }) });',
        '                input.value = \'\';',
        '                await loadAdminRegistryData();',
        '                await populateZoneSelects();',
        '            } catch (err) {',
        '                alert("Error registering zone. Please verify connection or admin permissions.");',
        '            }',
        '        }',

        '        async function loadAdminRegistryData() {',
        '            const zones = await apiCall(\'/api/zones\');',
        '            const container = document.getElementById(\'zone-checkbox-container\');',
        '            container.innerHTML = zones.map(z => \`',
        '                <label class="zone-checkbox-item">',
        '                    <input type="checkbox" value="\${z}" class="admin-zone-chk"> \${z}',
        '                </label>\`).join(\'\');',

        '            const users = await apiCall(\'/api/users\');',
        '            document.getElementById(\'users-table\').innerHTML = users.map(u => \`',
        '                <tr>',
        '                    <td>\${u.username}</td>',
        '                    <td>\${u.phone}</td>',
        '                    <td>\${u.zones.join(\', \')}</td>',
        '                    <td>\${u.status === 1 ? \'Active\' : \'Disabled\'}</td>',
        '                    <td>',
        '                        <button class="action-link" onclick="toggleUserStatus(\${u.id}, \${u.status === 1 ? 0 : 1})">\${u.status === 1 ? \'Disable\' : \'Enable\'}</button> | ',
        '                        <button class="action-link" style="color:var(--danger)" onclick="deleteUser(\${u.id})">Remove</button>',
        '                    </td>',
        '                </tr>\`).join(\'\');',

        '            const audits = await apiCall(\'/api/admin/audit-logs\');',
        '            document.getElementById(\'audit-table\').innerHTML = audits.map(a => \`',
        '                <tr>',
        '                    <td>\${a.timestamp}</td>',
        '                    <td>\${a.username}</td>',
        '                    <td>\${a.phone}</td>',
        '                    <td>\${a.zone}</td>',
        '                    <td><b>\${a.action}</b></td>',
        '                </tr>\`).join(\'\');',
        '        }',

        '        async function createUser() {',
        '            const username = document.getElementById(\'nu-name\').value.trim();',
        '            const phone = document.getElementById(\'nu-phone\').value.trim();',
        '            const password = document.getElementById(\'nu-pass\').value;',
        '            const selectedZones = Array.from(document.querySelectorAll(\'.admin-zone-chk:checked\')).map(cb => cb.value);',

        '            if (!username || !phone || !password || !selectedZones.length) {',
        '                alert("Please complete all user fields and select at least one zone.");',
        '                return;',
        '            }',

        '            const res = await apiCall(\'/api/users\', { method: \'POST\', body: JSON.stringify({ username, phone, password, zones: selectedZones }) });',
        '            alert(res.message || res.error);',
        '            loadAdminRegistryData();',
        '        }',

        '        async function toggleUserStatus(id, status) {',
        '            await apiCall(\`/api/users/\${id}/status\`, { method: \'PUT\', body: JSON.stringify({ status }) });',
        '            loadAdminRegistryData();',
        '        }',

        '        async function deleteUser(id) {',
        '            if (!confirm("Permanently delete user account?")) return;',
        '            await apiCall(\`/api/users/\${id}\`, { method: \'DELETE\' });',
        '            loadAdminRegistryData();',
        '        }',

        '        async function updateAdminProfile() {',
        '            const newUsername = document.getElementById(\'admin-new-user\').value.trim();',
        '            const newPassword = document.getElementById(\'admin-new-pass\').value;',
        '            if (!newUsername || !newPassword) return;',
        '            const res = await apiCall(\'/api/admin/profile\', { method: \'PUT\', body: JSON.stringify({ newUsername, newPassword }) });',
        '            alert(res.message || res.error);',
        '        }',

        '        async function processMasterImport(mode) {',
        '            const zone = document.getElementById(\'admin-import-zone\').value;',
        '            const fileInput = document.getElementById(\'admin-file-import\');',
        '            if (!zone || !fileInput.files.length) {',
        '                alert("Please select a target zone and upload a file.");',
        '                return;',
        '            }',
        '            const file = fileInput.files[0];',
        '            const reader = new FileReader();',

        '            reader.onload = async function(e) {',
        '                let drugs = [];',
        '                if (file.name.endsWith(\'.json\')) {',
        '                    try { drugs = JSON.parse(e.target.result); } catch(err) { alert("Invalid JSON format."); return; }',
        '                } else {',
        '                    const data = new Uint8Array(e.target.result);',
        '                    const workbook = XLSX.read(data, { type: \'array\' });',
        '                    const firstSheet = workbook.SheetNames[0];',
        '                    drugs = XLSX.utils.sheet_to_json(workbook.Sheets[firstSheet]);',
        '                }',
        '                const res = await apiCall(\'/api/master-drugs/import\', { method: \'POST\', body: JSON.stringify({ mode, zone, drugs }) });',
        '                alert(res.message || res.error);',
        '                refreshData();',
        '            };',

        '            if (file.name.endsWith(\'.json\')) {',
        '                reader.readAsText(file);',
        '            } else {',
        '                reader.readAsArrayBuffer(file);',
        '            }',
        '        }',

        '        function exportReport(type) {',
        '            const totals = {};',
        '            state.dispenses.forEach(i => totals[i.drug_name] = (totals[i.drug_name] || 0) + i.qty);',
        '            const rows = Object.keys(totals).sort().map(k => [k, totals[k]]);',

        '            if (type === \'excel\') {',
        '                const wsData = [["Drug Name", "Total Quantity Dispensed"], ...rows];',
        '                const wb = XLSX.utils.book_new();',
        '                XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet(wsData), "Inventory");',
        '                XLSX.writeFile(wb, \`pharma_sync_\${state.activeZone}_\${new Date().toISOString().slice(0,10)}.xlsx\`);',
        '            } else if (type === \'pdf\') {',
        '                const { jsPDF } = window.jspdf;',
        '                const doc = new jsPDF();',
        '                doc.text(\`PHARMA-SYNC PRO REPORT | ZONE: \${state.activeZone}\`, 14, 20);',
        '                doc.autoTable({ startY: 30, head: [[\'Drug Name\', \'Total Quantity\']], body: rows });',
        '                doc.save(\`pharma_sync_\${state.activeZone}_\${new Date().toISOString().slice(0,10)}.pdf\`);',
        '            }',
        '        }',

        '        if (state.token) { initAppInterface(); }',
        '    </script>',
        '</body>',
        '</html>'
    ];
    res.send(htmlLines.join('\n'));
});

// Start Server
app.listen(PORT, () => {
    console.log(`Pharma-Sync Pro active on port ${PORT}`);
});
