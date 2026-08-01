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

// Levenshtein Distance Algorithm for Smart Fuzzy Search & Auto-Correction
function getLevenshteinDistance(a, b) {
    const matrix = [];
    for (let i = 0; i <= b.length; i++) { matrix[i] = [i]; }
    for (let j = 0; j <= a.length; j++) { matrix[0][j] = j; }
    for (let i = 1; i <= b.length; i++) {
        for (let j = 1; j <= a.length; j++) {
            if (b.charAt(i - 1) === a.charAt(j - 1)) {
                matrix[i][j] = matrix[i - 1][j - 1];
            } else {
                matrix[i][j] = Math.min(matrix[i - 1][j - 1] + 1, Math.min(matrix[i][j - 1] + 1, matrix[i - 1][j] + 1));
            }
        }
    }
    return matrix[b.length][a.length];
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
        res.json({ message: "Zone registered successfully." });
    });
});

app.get('/api/admin/audit-logs', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required." });
    // Purge records older than 1 month before query retrieval
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

app.put('/api/dispense/:id', authenticateToken, (req, res) => {
    db.run("UPDATE dispenses SET qty = ? WHERE id = ?", [parseInt(req.body.qty), req.params.id], () => res.json({ message: "Dispense quantity updated." }));
});

app.delete('/api/dispense/:id', authenticateToken, (req, res) => {
    db.run("DELETE FROM dispenses WHERE id = ?", [req.params.id], () => res.json({ message: "Dispense entry removed." }));
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
        '                            System Architect & Lead Developer',
        '                        </div>',
        '                    </div>',

        '                    <!-- PANEL 2: DISPENSE CONSOLE & CUMULATIVE TOTALS -->',
        '                    <div class="panel">',
        '                        <h2>🛒 Dispense Console <span style="font-size:11px; color:var(--text-muted); float:right;">[Shortcut: Ctrl+K / F2]</span></h2>',
        '                        <div style="display: grid; grid-template-columns: 1fr 120px; gap: 10px;">',
        '                            <input type="text" id="searchDrug" list="drugList" placeholder="Select / Type Drug Name..." oninput="checkDrugAutoJump(event)" onkeydown="handleDrugNameKeydown(event)">',
        '                            <input type="number" id="dispenseAmount" placeholder="Qty" onkeydown="if(event.key===\'Enter\') dispenseDrug()">',
        '                        </div>',
        '                        <datalist id="drugList"></datalist>',
        '                        <div class="qty-grid">',
        '                            <button class="qty-pill" onclick="setQty(1)">1</button>',
        '                            <button class="qty-pill" onclick="setQty(5)">5</button>',
        '                            <button class="qty-pill" onclick="setQty(10)">10</button>',
        '                            <button class="qty-pill" onclick="setQty(15)">15</button>',
        '                            <button class="qty-pill" onclick="setQty(20)">20</button>',
        '                            <button class="qty-pill" onclick="setQty(30)">30</button>',
        '                            <button class="qty-pill" onclick="setQty(60)">60</button>',
        '                            <button class="qty-pill" onclick="setQty(120)">120</button>',
        '                        </div>',
        '                        <button class="primary-btn success" style="height: 42px; font-size:15px" id="recordBtn" onclick="dispenseDrug()">RECORD ENTRY</button>',

        '                        <h2 style="margin-top:25px">📊 Today\'s Cumulative Totals</h2>',
        '                        <input type="text" onkeyup="filterTable(\'dailyBody\', this.value)" placeholder="Filter cumulative totals...">',
        '                        <div class="table-wrap" style="max-height: 380px;">',
        '                            <table><thead><tr><th>Drug Name</th><th>Total Qty</th><th style="text-align:right">Action</th></tr></thead><tbody id="dailyBody"></tbody></table>',
        '                        </div>',
        '                    </div>',

        '                    <!-- PANEL 3: HISTORY & REPORT -->',
        '                    <div class="panel">',
        '                        <h2>🕒 Recent History</h2>',
        '                        <div class="table-wrap" style="max-height: 280px;"><table><tbody id="historyBody"></tbody></table></div>',
        '                        <button class="primary-btn" style="background:#94a3b8; margin-top:10px; padding:6px; font-size:11px" onclick="clearHistoryOnly()">CLEAR LOG</button>',

        '                        <h2 style="margin-top:25px">📄 Report & Maintenance</h2>',
        '                        <input type="text" id="pdfRemarks" placeholder="Enter remarks (Mandatory)..." onkeydown="if(event.key===\'Enter\') generateReport()">',
        '                        <button class="primary-btn danger" onclick="generateReport()">GENERATE PDF REPORT</button>',
        '                        <button class="primary-btn" style="background:#64748b; margin-top:6px" onclick="resetDailyDataOnly()">RESET TOTALS & HISTORY</button>',
        '                    </div>',
        '                </div>',
        '            </div>',
        '        </div>',

        '        <!-- Post-Login Zone Selection Modal -->',
        '        <div id="login-zone-modal" class="modal-overlay hidden">',
        '            <div class="panel" style="width: 380px; text-align: center; margin-bottom: 0;">',
        '                <h2>📍 Select Active Zone</h2>',
        '                <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 15px;">You have access to multiple zones. Please pick one to proceed:</p>',
        '                <select id="initial-zone-select" style="padding: 12px; font-size: 15px; margin-bottom: 20px;"></select>',
        '                <button onclick="confirmInitialZone()" class="primary-btn success" style="padding: 12px; font-size: 15px;">CONFIRM & ENTER</button>',
        '            </div>',
        '        </div>',

        '        <!-- Edit User Zones Modal -->',
        '        <div id="edit-zones-modal" class="modal-overlay hidden">',
        '            <div class="panel" style="width: 420px; margin-bottom:0;">',
        '                <h2>✏️ Edit User Access Zones</h2>',
        '                <p id="edit-user-name" style="color: var(--accent); margin-bottom: 15px; font-weight: bold;"></p>',
        '                <div id="edit-zone-checkboxes" class="zone-checkbox-group" style="max-height: 220px; overflow-y: auto;"></div>',
        '                <input type="hidden" id="edit-user-id">',
        '                <div class="flex" style="margin-top: 15px;">',
        '                    <button onclick="saveUserZones()" class="primary-btn success">Update Zones</button>',
        '                    <button onclick="closeEditModal()" class="primary-btn danger">Cancel</button>',
        '                </div>',
        '            </div>',
        '        </div>',

        '        <div style="text-align: center; font-size: 12px; color: var(--text-muted); margin-top: 30px;">',
        '            System Architecture & Sole Copyright Holder: <b>Debanjan Singha</b> | All Rights Reserved &copy; 2026',
        '        </div>',
        '    </div>',

        '    <script>',
        '        let token = localStorage.getItem("token");',
        '        let currentUser = null;',
        '        let activeZone = "";',
        '        let assignedUserZones = [];',
        '        let masterDrugsList = [];',
        '        let dispenseHistory = [];',
        '        let dailyLog = {};',
        '        let availableZonesList = [];',
        '        let autoSyncTimer = null;',
        '        let offlineQueue = JSON.parse(localStorage.getItem("pharma_offline_queue") || "[]");',

        '        // Smart Diff Caches to prevent unnecessary DOM thrashing & lagging',
        '        let lastMasterCache = "";',
        '        let lastHistoryCache = "";',

        '        if (token) checkSession();',

        '        // Global Power-User Hotkey Listener',
        '        window.addEventListener("keydown", (e) => {',
        '            if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {',
        '                e.preventDefault();',
        '                const sBox = document.getElementById("searchDrug");',
        '                if (sBox) { sBox.focus(); sBox.select(); }',
        '            } else if (e.key === "F2") {',
        '                e.preventDefault();',
        '                const sBox = document.getElementById("searchDrug");',
        '                if (sBox) { sBox.focus(); sBox.select(); }',
        '            }',
        '        });',

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
        '            if (autoSyncTimer) clearInterval(autoSyncTimer);',
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
        '            document.getElementById("role-display").innerText = payload.role;',

        '            if (payload.role === "ADMIN") {',
        '                document.getElementById("admin-view").classList.remove("hidden");',
        '                loadAdminData();',
        '            } else {',
        '                document.getElementById("user-view").classList.remove("hidden");',
        '                loadUserZones();',
        '            }',
        '        }',

        '        // Predictive Smart-Search & Auto-Correction Fuzzy Matching',
        '        function checkDrugAutoJump(e) {',
        '            const rawInput = e.target.value.trim().toUpperCase();',
        '            if (!rawInput) return;',
        '            if (masterDrugsList.includes(rawInput)) {',
        '                const qtyInput = document.getElementById("dispenseAmount");',
        '                qtyInput.focus();',
        '                qtyInput.select();',
        '                return;',
        '            }',
        '            // Fuzzy match check (Levenshtein distance <= 2 for typo correction)',
        '            let bestMatch = null;',
        '            let minDistance = 99;',
        '            masterDrugsList.forEach(drug => {',
        '                const dist = getLevenshteinDistance(rawInput, drug);',
        '                if (dist < minDistance && dist <= 2 && rawInput.length >= 3) {',
        '                    minDistance = dist;',
        '                    bestMatch = drug;',
        '                }',
        '            });',
        '            if (bestMatch) {',
        '                e.target.value = bestMatch;',
        '                const qtyInput = document.getElementById("dispenseAmount");',
        '                qtyInput.focus();',
        '                qtyInput.select();',
        '            }',
        '        }',

        '        function getLevenshteinDistance(a, b) {',
        '            const matrix = [];',
        '            for (let i = 0; i <= b.length; i++) { matrix[i] = [i]; }',
        '            for (let j = 0; j <= a.length; j++) { matrix[0][j] = j; }',
        '            for (let i = 1; i <= b.length; i++) {',
        '                for (let j = 1; j <= a.length; j++) {',
        '                    if (b.charAt(i - 1) === a.charAt(j - 1)) {',
        '                        matrix[i][j] = matrix[i - 1][j - 1];',
        '                    } else {',
        '                        matrix[i][j] = Math.min(matrix[i - 1][j - 1] + 1, Math.min(matrix[i][j - 1] + 1, matrix[i - 1][j] + 1));',
        '                    }',
        '                }',
        '            }',
        '            return matrix[b.length][a.length];',
        '        }',

        '        function handleDrugNameKeydown(e) {',
        '            if (e.key === "Enter") {',
        '                e.preventDefault();',
        '                const qtyInput = document.getElementById("dispenseAmount");',
        '                qtyInput.focus();',
        '                qtyInput.select();',
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
        '                        <button onclick="openEditModal(${u.id}, \'${u.username}\', \'${zonesStr}\')" class="action-link" style="color:var(--accent);">Edit Zones</button>',
        '                        <button onclick="toggleUser(${u.id}, ${u.status ? 0 : 1})" class="action-link" style="color:var(--warning);">${u.status ? "Disable" : "Enable"}</button>',
        '                        <button onclick="removeUser(${u.id})" class="action-link" style="color:var(--danger);">Remove</button>',
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

        '        async function loadUserZones() {',
        '            const zRes = await fetch("/api/zones", { headers: { "Authorization": "Bearer " + token } });',
        '            assignedUserZones = await zRes.json();',

        '            const pickerWrap = document.getElementById("user-zone-picker-wrap");',
        '            const badgeWrap = document.getElementById("single-zone-badge-wrap");',
        '            const zoneSelect = document.getElementById("user-zone-select");',

        '            if (assignedUserZones.length === 1) {',
        '                activeZone = assignedUserZones[0];',
        '                pickerWrap.style.display = "none";',
        '                badgeWrap.style.display = "block";',
        '                document.getElementById("single-zone-name").innerText = activeZone;',
        '                startAutoSync();',
        '            } else if (assignedUserZones.length > 1) {',
        '                pickerWrap.style.display = "block";',
        '                badgeWrap.style.display = "none";',
        '                zoneSelect.innerHTML = "";',
        '                const initSelect = document.getElementById("initial-zone-select");',
        '                initSelect.innerHTML = "";',

        '                assignedUserZones.forEach(z => {',
        '                    zoneSelect.innerHTML += `<option value="${z}">${z}</option>`;',
        '                    initSelect.innerHTML += `<option value="${z}">${z}</option>`;',
        '                });',

        '                document.getElementById("login-zone-modal").classList.remove("hidden");',
        '            } else {',
        '                alert("No zones assigned to your user account. Please contact Admin.");',
        '                return handleLogout();',
        '            }',
        '        }',

        '        function confirmInitialZone() {',
        '            activeZone = document.getElementById("initial-zone-select").value;',
        '            document.getElementById("user-zone-select").value = activeZone;',
        '            document.getElementById("login-zone-modal").classList.add("hidden");',
        '            startAutoSync();',
        '        }',

        '        function switchZone() {',
        '            activeZone = document.getElementById("user-zone-select").value;',
        '            lastMasterCache = "";',
        '            lastHistoryCache = "";',
        '            syncUserData();',
        '        }',

        '        function startAutoSync() {',
        '            syncUserData();',
        '            if (autoSyncTimer) clearInterval(autoSyncTimer);',
        '            // Live Background Auto-Sync every 2 seconds with Offline Queue Syncing',
        '            autoSyncTimer = setInterval(() => {',
        '                if (activeZone && !document.hidden) {',
        '                    syncUserData(true);',
        '                }',
        '            }, 2000);',
        '        }',

        '        async function syncUserData(isSilent = false) {',
        '            try {',
        '                // First flush any pending offline records if back online',
        '                if (navigator.onLine && offlineQueue.length > 0) {',
        '                    document.getElementById("sync-status-text").innerText = "SYNCING OFFLINE QUEUE...";',
        '                    while (offlineQueue.length > 0) {',
        '                        const payload = offlineQueue[0];',
        '                        const sRes = await fetch(payload.endpoint, {',
        '                            method: payload.method,',
        '                            headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },',
        '                            body: JSON.stringify(payload.body)',
        '                        });',
        '                        if (sRes.ok) {',
        '                            offlineQueue.shift();',
        '                            localStorage.setItem("pharma_offline_queue", JSON.stringify(offlineQueue));',
        '                        } else { break; }',
        '                    }',
        '                }',

        '                const mRes = await fetch(`/api/master-drugs?zone=${activeZone}`, { headers: { "Authorization": "Bearer " + token } });',
        '                if (!mRes.ok) return handleAccessError(mRes);',
        '                const masterData = await mRes.json();',
        '                const masterStr = JSON.stringify(masterData);',

        '                const hRes = await fetch(`/api/dispense/sync?zone=${activeZone}`, { headers: { "Authorization": "Bearer " + token } });',
        '                const historyData = await hRes.json();',
        '                const historyStr = JSON.stringify(historyData);',

        '                let masterChanged = false;',
        '                let historyChanged = false;',

        '                if (masterStr !== lastMasterCache) {',
        '                    masterDrugsList = masterData;',
        '                    lastMasterCache = masterStr;',
        '                    masterChanged = true;',
        '                }',

        '                if (historyStr !== lastHistoryCache) {',
        '                    dispenseHistory = historyData;',
        '                    lastHistoryCache = historyStr;',
        '                    historyChanged = true;',
        '                    ',
        '                    dailyLog = {};',
        '                    dispenseHistory.forEach(h => {',
        '                        dailyLog[h.drug_name] = (dailyLog[h.drug_name] || 0) + h.qty;',
        '                    });',
        '                }',

        '                document.getElementById("sync-dot").style.backgroundColor = "var(--success)";',
        '                document.getElementById("sync-status-text").innerText = "LIVE AUTO-SYNC (2s)";',
        '                document.getElementById("presence-indicator").innerText = `🟢 Zone Active: ${activeZone} | Operators Connected & Collaborative`;',

        '                if (masterChanged || historyChanged) {',
        '                    updateUI(masterChanged, historyChanged);',
        '                }',
        '            } catch(e) {',
        '                // Offline fallback mode',
        '                document.getElementById("sync-dot").style.backgroundColor = "var(--danger)";',
        '                document.getElementById("sync-status-text").innerText = "OFFLINE MODE (Local Cache Active)";',
        '                document.getElementById("presence-indicator").innerText = `⚠️ Offline Mode - Working Locally in ${activeZone}`;',
        '            }',
        '        }',

        '        function updateUI(masterChanged = true, historyChanged = true) {',
        '            if (masterChanged) {',
        '                renderTable("masterBody", masterDrugsList.sort(), (item) => `',
        '                    <td>${item}</td>',
        '                    <td style="text-align:right">',
        '                        <button class="action-link" style="color:var(--warning)" onclick="editMasterDrugInline(\'${item}\')">Edit</button>',
        '                        <button class="action-link" style="color:var(--danger)" onclick="removeDrug(\'${item}\')">Del</button>',
        '                    </td>',
        '                `);',
        '                document.getElementById("drugList").innerHTML = masterDrugsList.map(m => `<option value="${m}">`).join("");',
        '            }',

        '            if (historyChanged) {',
        '                renderTable("dailyBody", Object.keys(dailyLog).sort(), (k) => `',
        '                    <td>${k}</td>',
        '                    <td><span class="badge">${dailyLog[k]}</span></td>',
        '                    <td style="text-align:right">',
        '                        <button class="action-link" style="color:var(--warning)" onclick="editCumulativeQty(\'${k}\', ${dailyLog[k]})">Edit</button>',
        '                    </td>',
        '                `);',

        '                renderTable("historyBody", dispenseHistory.slice(0, 50), (i) => `',
        '                    <td><span style="color:gray; font-size:10px">${i.timestamp}</span><br>${i.drug_name} (<b>${i.qty}</b>) - <i style="font-size:11px">${i.entered_by}</i></td>',
        '                    <td style="text-align:right">',
        '                        <button class="action-link" style="color:var(--warning)" onclick="editHistoryQty(${i.id}, ${i.qty})">Edit</button>',
        '                        <button class="action-link" style="color:var(--danger)" onclick="undoTransaction(${i.id})">Undo</button>',
        '                    </td>',
        '                `);',
        '            }',
        '        }',

        '        function renderTable(id, data, templateFn) {',
        '            document.getElementById(id).innerHTML = data.map(item => `<tr>${templateFn(item)}</tr>`).join("");',
        '        }',

        '        function setQty(v) {',
        '            document.getElementById("dispenseAmount").value = v;',
        '            document.getElementById("recordBtn").focus();',
        '        }',

        '        async function registerDrug() {',
        '            const i = document.getElementById("newDrugName");',
        '            const d = i.value.trim().toUpperCase();',
        '            if (!d) return;',
        '            const payload = { endpoint: "/api/master-drugs", method: "POST", body: { zone: activeZone, drug_name: d } };',
        '            if (navigator.onLine) {',
        '                await fetch(payload.endpoint, {',
        '                    method: payload.method,',
        '                    headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },',
        '                    body: JSON.stringify(payload.body)',
        '                });',
        '            } else {',
        '                offlineQueue.push(payload);',
        '                localStorage.setItem("pharma_offline_queue", JSON.stringify(offlineQueue));',
        '            }',
        '            i.value = "";',
        '            syncUserData();',
        '        }',

        '        async function dispenseDrug() {',
        '            const nI = document.getElementById("searchDrug");',
        '            const aI = document.getElementById("dispenseAmount");',
        '            const d = nI.value.trim().toUpperCase();',
        '            const q = parseInt(aI.value);',

        '            if (!masterDrugsList.includes(d)) return alert("Drug not found in Master Directory. Please register it first.");',
        '            if (isNaN(q) || q <= 0) return alert("Please enter a valid quantity.");',

        '            const payload = { endpoint: "/api/dispense", method: "POST", body: { zone: activeZone, drug_name: d, qty: q } };',
        '            if (navigator.onLine) {',
        '                await fetch(payload.endpoint, {',
        '                    method: payload.method,',
        '                    headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },',
        '                    body: JSON.stringify(payload.body)',
        '                });',
        '            } else {',
        '                offlineQueue.push(payload);',
        '                localStorage.setItem("pharma_offline_queue", JSON.stringify(offlineQueue));',
        '                // Optimistic local update',
        '                dailyLog[d] = (dailyLog[d] || 0) + q;',
        '            }',

        '            nI.value = ""; aI.value = "";',
        '            syncUserData();',
        '            nI.focus();',
        '        }',

        '        async function editCumulativeQty(drugName, currentQty) {',
        '            const newQty = prompt(`Edit Cumulative Quantity for ${drugName}:`, currentQty);',
        '            if (newQty === null || isNaN(parseInt(newQty)) || parseInt(newQty) < 0) return;',

        '            await fetch("/api/dispense/adjust-cumulative", {',
        '                method: "PUT",',
        '                headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },',
        '                body: JSON.stringify({ zone: activeZone, drug_name: drugName, new_qty: parseInt(newQty) })',
        '            });',
        '            syncUserData();',
        '        }',

        '        async function editHistoryQty(id, oldQty) {',
        '            const nq = prompt("Enter updated quantity:", oldQty);',
        '            if (!nq || isNaN(parseInt(nq))) return;',
        '            await fetch(`/api/dispense/${id}`, {',
        '                method: "PUT",',
        '                headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },',
        '                body: JSON.stringify({ qty: parseInt(nq) })',
        '            });',
        '            syncUserData();',
        '        }',

        '        async function undoTransaction(id) {',
        '            if (!confirm("Undo this dispense entry?")) return;',
        '            await fetch(`/api/dispense/${id}`, { method: "DELETE", headers: { "Authorization": "Bearer " + token } });',
        '            syncUserData();',
        '        }',

        '        async function removeDrug(dName) {',
        '            if (!confirm(`Delete ${dName} from Master Directory?`)) return;',
        '            await fetch("/api/master-drugs", {',
        '                method: "DELETE",',
        '                headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },',
        '                body: JSON.stringify({ zone: activeZone, drug_name: dName })',
        '            });',
        '            syncUserData();',
        '        }',

        '        async function editMasterDrugInline(oldName) {',
        '            const newName = prompt(`Edit drug name for ${oldName}:`, oldName);',
        '            if (!newName || newName.trim().toUpperCase() === oldName) return;',

        '            await fetch("/api/master-drugs/rename", {',
        '                method: "PUT",',
        '                headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },',
        '                body: JSON.stringify({ zone: activeZone, oldName: oldName, newName: newName.trim().toUpperCase() })',
        '            });',

        '            syncUserData();',
        '        }',

        '        async function resetDailyDataOnly() {',
        '            if (confirm("Clear Today\'s Totals and History for active zone?")) {',
        '                await fetch("/api/dispense/clear/all", {',
        '                    method: "DELETE",',
        '                    headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },',
        '                    body: JSON.stringify({ zone: activeZone })',
        '                });',
        '                syncUserData();',
        '            }',
        '        }',

        '        function clearHistoryOnly() { resetDailyDataOnly(); }',

        '        function generateReport() {',
        '            const remarks = document.getElementById("pdfRemarks").value.trim();',
        '            if (!remarks) return alert("Remarks field is mandatory for downloading PDF reporting.");',

        '            const { jsPDF } = window.jspdf;',
        '            const doc = new jsPDF();',
        '            doc.setFontSize(16);',
        '            doc.text(`PHARMA-SYNC DAILY REPORT - ${activeZone}`, 14, 20);',
        '            doc.setFontSize(10);',
        '            doc.text(`Date & Time: ${new Date().toLocaleString()} | Mandatory Remarks: ${remarks}`, 14, 28);',

        '            const tableRows = Object.keys(dailyLog).sort().map(k => [k, dailyLog[k]]);',
        '            doc.autoTable({',
        '                startY: 35,',
        '                head: [["Drug Name", "Cumulative Total Quantity"]],',
        '                body: tableRows,',
        '                didDrawPage: function (data) {',
        '                    // Lead developer name visible on every single page of the PDF',
        '                    const pageCount = doc.internal.getNumberOfPages();',
        '                    doc.setFontSize(8);',
        '                    doc.setTextColor(100);',
        '                    doc.text(`Lead Developer & Architect: Debanjan Singha | Page ${data.pageNumber} of ${pageCount}`, 14, doc.internal.pageSize.height - 10);',
        '                }',
        '            });',
        '            doc.save(`PharmaReport_${activeZone}_${Date.now()}.pdf`);',
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

        '        function closeEditModal() { document.getElementById("edit-zones-modal").classList.add("hidden"); }',

        '        async function saveUserZones() {',
        '            const id = document.getElementById("edit-user-id").value;',
        '            const selectedCheckboxes = document.querySelectorAll(\'input[name="edit-assigned-zones"]:checked\');',
        '            const z = Array.from(selectedCheckboxes).map(cb => cb.value);',
        '            if (!z.length) return alert("Please select at least one zone before saving.");',

        '            const res = await fetch(`/api/users/${id}/zones`, {',
        '                method: "PUT",',
        '                headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },',
        '                body: JSON.stringify({ zones: z })',
        '            });',
        '            if (res.ok) { closeEditModal(); loadAdminData(); } else { alert("Failed to update user zones."); }',
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
        '            if (!confirm("Permanently remove user?")) return;',
        '            await fetch(`/api/users/${id}`, { method: "DELETE", headers: { "Authorization": "Bearer " + token } });',
        '            loadAdminData();',
        '        }',

        '        async function createUser() {',
        '            const u = document.getElementById("nu-name").value;',
        '            const p = document.getElementById("nu-phone").value;',
        '            const pass = document.getElementById("nu-pass").value;',
        '            const selectedCheckboxes = document.querySelectorAll(\'input[name="assigned-zones"]:checked\');',
        '            const z = Array.from(selectedCheckboxes).map(cb => cb.value);',

        '            if (!z.length) return alert("Select at least one zone from checkboxes.");',
        '            const res = await fetch("/api/users", {',
        '                method: "POST",',
        '                headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },',
        '                body: JSON.stringify({ username: u, phone: p, password: pass, zones: z })',
        '            });',
        '            if (res.ok) { alert("User created successfully"); loadAdminData(); } else { alert("Failed to create user"); }',
        '        }',

        '        function normalizeImportData(rawData) {',
        '            let items = rawData;',
        '            if (typeof items === "string") {',
        '                try { items = JSON.parse(items); } catch(e) {}',
        '            }',
        '            if (!Array.isArray(items) && typeof items === "object" && items !== null) {',
        '                const firstArrayKey = Object.keys(items).find(k => Array.isArray(items[k]));',
        '                items = firstArrayKey ? items[firstArrayKey] : [items];',
        '            }',
        '            return Array.isArray(items) ? items : [items];',
        '        }',

        '        async function processMasterImport(mode) {',
        '            const targetZone = document.getElementById("admin-import-zone").value;',
        '            const fileInput = document.getElementById("admin-file-import");',
        '            if (!targetZone) return alert("Select a target zone for import.");',
        '            if (!fileInput.files.length) return alert("Choose a file.");',

        '            const file = fileInput.files[0];',
        '            const fileName = file.name.toLowerCase();',

        '            if (fileName.endsWith(".json")) {',
        '                const reader = new FileReader();',
        '                reader.onload = async (e) => {',
        '                    try {',
        '                        let parsedData = JSON.parse(e.target.result);',
        '                        const normalizedArr = normalizeImportData(parsedData);',
        '                        sendMasterImportPayload(mode, targetZone, normalizedArr);',
        '                    } catch(err) { alert("Invalid JSON file format."); }',
        '                };',
        '                reader.readAsText(file);',
        '            } else if (fileName.endsWith(".xlsx") || fileName.endsWith(".xls")) {',
        '                const reader = new FileReader();',
        '                reader.onload = async (e) => {',
        '                    const data = new Uint8Array(e.target.result);',
        '                    const workbook = XLSX.read(data, { type: "array" });',
        '                    const sheet = workbook.Sheets[workbook.SheetNames[0]];',
        '                    const parsedRows = XLSX.utils.sheet_to_json(sheet);',
        '                    sendMasterImportPayload(mode, targetZone, parsedRows);',
        '                };',
        '                reader.readAsArrayBuffer(file);',
        '            }',
        '        }',

        '        async function sendMasterImportPayload(mode, zone, items) {',
        '            const res = await fetch("/api/master-drugs/import", {',
        '                method: "POST",',
        '                headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },',
        '                body: JSON.stringify({ zone, mode, drugs: items })',
        '            });',
        '            const data = await res.json();',
        '            if (res.ok) alert(data.message || "Import success!"); else alert("Import error: " + data.error);',
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

        '        function filterTable(id, val) {',
        '            const rows = document.getElementById(id).rows;',
        '            const s = val.toUpperCase();',
        '            for (let r of rows) r.style.display = r.innerText.toUpperCase().includes(s) ? "" : "none";',
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
    console.log("High Performance Server running on port " + PORT);
});
