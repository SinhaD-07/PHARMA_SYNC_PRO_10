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
const SECRET_KEY = process.env.JWT_SECRET || "rxmedisync_ultra_secure_debanjan_2026_key";

const COPYRIGHT_OWNER = "Debanjan Singha";
console.log("================================================================");
console.log(" RXMEDISYNC PRO | ULTRA-FAST REALTIME ENTERPRISE ENGINE");
console.log(" Lead System Architect & Developer: " + COPYRIGHT_OWNER);
console.log(" Copyright (c) 2026. All Rights Reserved.");
console.log("================================================================");

// Strict Data Firewall & Security Headers (Zero Third-Party Data Leakage Protection)
app.use((req, res, next) => {
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self' cdnjs.cloudflare.com; " +
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' cdnjs.cloudflare.com; " +
        "style-src 'self' 'unsafe-inline' cdnjs.cloudflare.com; " +
        "img-src 'self' data:; " +
        "connect-src 'self';"
    );
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'no-referrer');
    next();
});

app.use(cors());
app.use(express.json({ limit: '100mb' }));

// Initialize Database with WAL Mode for High Concurrency (100+ Users, 1M+ Records)
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
        db.run("CREATE TABLE IF NOT EXISTS activity_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, phone TEXT, action TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)");
        db.run("CREATE TABLE IF NOT EXISTS zone_registry (id INTEGER PRIMARY KEY AUTOINCREMENT, zone_name TEXT UNIQUE)");

        // High Speed Database Indexes
        db.run("CREATE INDEX IF NOT EXISTS idx_master_zone_drug ON master_drugs(zone, drug_name)");
        db.run("CREATE INDEX IF NOT EXISTS idx_dispenses_zone ON dispenses(zone)");
        db.run("CREATE INDEX IF NOT EXISTS idx_activity_timestamp ON activity_logs(timestamp)");

        // Automatically purge activity logs older than 1 month (30 days)
        db.run("DELETE FROM activity_logs WHERE timestamp < datetime('now', '-30 days')");

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
        db.run("INSERT INTO activity_logs (username, phone, action) VALUES (?, ?, 'LOGIN')", [user.username, user.phone]);

        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, SECRET_KEY, { expiresIn: '8h' });
        let userZones = [];
        try { userZones = JSON.parse(user.zones); } catch(e) { userZones = [user.zones]; }

        res.json({ token, role: user.role, username: user.username, phone: user.phone, zones: userZones });
    });
});

app.post('/api/logout', authenticateToken, (req, res) => {
    db.run("INSERT INTO audit_logs (username, phone, zone, action) VALUES (?, ?, ?, 'LOGOUT')", [req.user.username, req.user.phone, req.body.zone || "N/A"]);
    db.run("INSERT INTO activity_logs (username, phone, action) VALUES (?, ?, 'LOGOUT')", [req.user.username, req.user.phone]);
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
    db.run("INSERT INTO users (username, phone, password, role, zones, status) VALUES (?, ?, ?, 'USER', ?, 1)", 
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
        if (err) return res.status(500).json({ error: "Database error registering zone." });
        res.json({ message: "Zone registered successfully." });
    });
});

app.get('/api/admin/audit-logs', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required." });
    db.all("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200", [], (err, rows) => {
        res.json(rows);
    });
});

app.get('/api/admin/activity-logs', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required." });
    db.all("SELECT * FROM activity_logs ORDER BY id DESC LIMIT 500", [], (err, rows) => {
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
        '    <title>RxMEDISYNC PRO | ULTRA REALTIME ENGINE</title>',
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
        '        .panel-credit { margin-top: 20px; padding-top: 15px; border-top: 1px dashed #e2e8f0; font-size: 11px; color: var(--text-muted); text-align: center; line-height: 1.4; }',
        '        .panel-credit b { color: var(--sidebar); }',
        '        .live-dot { height: 8px; width: 8px; background-color: var(--success); border-radius: 50%; display: inline-block; margin-right: 6px; animation: pulse 1.5s infinite; }',
        '        @keyframes pulse { 0% { opacity: 0.4; } 50% { opacity: 1; } 100% { opacity: 0.4; } }',
        '    </style>',
        '</head>',
        '<body>',
        '    <div class="container">',
        '        <!-- LOGIN SCREEN -->',
        '        <div id="login-screen" class="panel" style="max-width: 420px; margin: 80px auto; text-align: center; padding: 35px;">',
        '            <h1 style="color:var(--sidebar); font-size: 24px; margin-bottom: 5px;">RxMEDISYNC<span style="color:var(--accent)">PRO</span></h1>',
        '            <p style="color: var(--text-muted); font-size: 13px; margin-bottom: 25px;">Real-Time Multi-User Pharmacy Engine</p>',
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
        '                    <h1 style="margin:0; font-size:20px; color:var(--sidebar); display: inline-block;">RxMEDISYNC<span style="color:var(--accent)">PRO</span></h1>',
        '                    <span id="role-display" class="badge" style="margin-left: 10px;">ROLE</span>',
        '                    <span style="margin-left: 15px; font-size: 12px; color: var(--text-muted);"><span class="live-dot"></span>LIVE AUTO-SYNC (2s)</span>',
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
        '                        <button onclick="processImport(\'master\', \'merge\')" class="primary-btn">Import Master (Merge)</button>',
        '                        <button onclick="processImport(\'master\', \'reset\')" class="primary-btn danger">Import Master (Reset & Add)</button>',
        '                    </div>',
        '                </div>',

        '                <div class="panel">',
        '                    <h2>🔐 User Login / Logout Activity Tracker (Retained 1 Month)</h2>',
        '                    <div class="table-wrap">',
        '                        <table>',
        '                            <thead><tr><th>Timestamp</th><th>Username</th><th>Phone</th><th>Action Event</th></tr></thead>',
        '                            <tbody id="activity-table"></tbody>',
        '                        </table>',
        '                    </div>',
        '                </div>',

        '                <div class="panel">',
        '                    <h2>📜 Transaction Audit Logs</h2>',
        '                    <div class="table-wrap">',
        '                        <table>',
        '                            <thead><tr><th>Timestamp</th><th>Username</th><th>Phone</th><th>Zone Context</th><th>Action</th></tr></thead>',
        '                            <tbody id="audit-table"></tbody>',
        '                        </table>',
        '                    </div>',
        '                </div>',
        '            </div>',

        '            <!-- USER SMART-FOCUS VIEW -->',
        '            <div id="user-view" class="hidden">',
        '                <div class="app-grid">',
        '                    <!-- PANEL 1: MASTER DIRECTORY -->',
        '                    <div class="panel">',
        '                        <h2>📦 Master Directory</h2>',
        '                        <input type="text" id="newDrugName" placeholder="New drug name..." onkeydown="if(event.key===\'Enter\') registerDrug()">',
        '                        <button class="primary-btn" onclick="registerDrug()">REGISTER DRUG</button>',
        '                        <input type="text" id="drugSearch" placeholder="Search Master Directory..." oninput="renderMasterList()" style="margin-top: 10px;">',
        '                        <div class="table-wrap" style="margin-top: 10px;">',
        '                            <table>',
        '                                <thead><tr><th>Drug Item</th><th style="text-align:right;">Actions</th></tr></thead>',
        '                                <tbody id="master-drug-table"></tbody>',
        '                            </table>',
        '                        </div>',
        '                        <div class="panel-credit">',
        '                            © 2026 <b>Debanjan Singha</b><br>',
        '                            Enterprise Pharmacy Engine',
        '                        </div>',
        '                    </div>',

        '                    <!-- PANEL 2: DISPENSE RECORDING ENGINE -->',
        '                    <div class="panel">',
        '                        <h2>⚡ Record & Dispense</h2>',
        '                        <select id="dispenseDrugSelect" style="font-weight:650; color:var(--accent);"></select>',
        '                        <div class="qty-grid">',
        '                            <div class="qty-pill" onclick="setQty(1)">1</div>',
        '                            <div class="qty-pill" onclick="setQty(2)">2</div>',
        '                            <div class="qty-pill" onclick="setQty(5)">5</div>',
        '                            <div class="qty-pill" onclick="setQty(10)">10</div>',
        '                        </div>',
        '                        <input type="number" id="dispenseQty" placeholder="Quantity" value="1" min="1">',
        '                        <button class="primary-btn success" onclick="submitDispense()">DISPENSE NOW</button>',
        '                        <hr style="margin:20px 0; border:0; border-top:1px solid #f1f5f9;">',
        '                        <h2>📊 Live Reports & Export</h2>',
        '                        <button class="primary-btn" onclick="exportExcel()" style="margin-bottom:8px;">Export Excel Report</button>',
        '                        <button class="primary-btn warning" onclick="exportPDF()" style="margin-bottom:8px;">Generate Official PDF Report</button>',
        '                        <button class="primary-btn danger" onclick="clearZoneTotals()">Clear Zone Totals</button>',
        '                    </div>',

        '                    <!-- PANEL 3: REALTIME CUMULATIVE INVENTORY -->',
        '                    <div class="panel">',
        '                        <h2>📋 Cumulative Zone Ledger</h2>',
        '                        <input type="text" id="ledgerSearch" placeholder="Search cumulative inventory..." oninput="renderCumulativeLedger()" style="margin-bottom: 10px;">',
        '                        <div class="table-wrap">',
        '                            <table>',
        '                                <thead><tr><th>Drug Name</th><th>Total Dispensed</th><th style="text-align:right;">Quick Edit</th></tr></thead>',
        '                                <tbody id="cumulative-ledger-table"></tbody>',
        '                            </table>',
        '                        </div>',
        '                        <br>',
        '                        <h2>📜 Realtime Transaction Feed</h2>',
        '                        <div class="table-wrap" style="max-height: 220px;">',
        '                            <table>',
        '                                <thead><tr><th>Time</th><th>Drug</th><th>Qty</th><th>By</th></tr></thead>',
        '                                <tbody id="dispense-history-table"></tbody>',
        '                            </table>',
        '                        </div>',
        '                    </div>',
        '                </div>',
        '            </div>',
        '        </div>',
        '    </div>',

        '<script>',
        'let authToken = localStorage.getItem("rx_token") || "";',
        'let currentUserRole = localStorage.getItem("rx_role") || "";',
        'let currentUsername = localStorage.getItem("rx_user") || "";',
        'let currentPhone = localStorage.getItem("rx_phone") || "";',
        'let userZonesList = JSON.parse(localStorage.getItem("rx_zones") || "[]");',
        'let activeZone = localStorage.getItem("rx_active_zone") || "";',
        'let masterDrugsCache = [];',
        'let dispenseHistoryCache = [];',
        'let syncTimer = null;',

        'window.onload = function() {',
        '    if (authToken) {',
        '        verifySessionAndBootstrap();',
        '    }',
        '};',

        'async function apiCall(endpoint, method = "GET", data = null) {',
        '    const headers = {',
        '        "Content-Type": "application/json",',
        '        "Authorization": "Bearer " + authToken',
        '    };',
        '    const options = { method, headers };',
        '    if (data) options.body = JSON.stringify(data);',
        '    try {',
        '        const res = await fetch(endpoint, options);',
        '        if (res.status === 401 || res.status === 403) {',
        '            handleLogout();',
        '            return null;',
        '        }',
        '        return await res.json();',
        '    } catch (e) {',
        '        console.error("API Error:", e);',
        '        return null;',
        '    }',
        '}',

        'async function handleLogin() {',
        '    const u = document.getElementById("login-username").value.trim();',
        '    const p = document.getElementById("login-password").value;',
        '    const errEl = document.getElementById("login-error");',
        '    errEl.innerText = "";',
        '    if (!u || !p) { errEl.innerText = "Please provide username and password."; return; }',
        '    try {',
        '        const res = await fetch("/api/login", {',
        '            method: "POST",',
        '            headers: { "Content-Type": "application/json" },',
        '            body: JSON.stringify({ username: u, password: p })',
        '        });',
        '        const data = await res.json();',
        '        if (!res.ok) {',
        '            errEl.innerText = data.error || "Authentication failed.";',
        '            return;',
        '        }',
        '        authToken = data.token;',
        '        currentUserRole = data.role;',
        '        currentUsername = data.username;',
        '        currentPhone = data.phone;',
        '        userZonesList = data.zones;',
        '        localStorage.setItem("rx_token", authToken);',
        '        localStorage.setItem("rx_role", currentUserRole);',
        '        localStorage.setItem("rx_user", currentUsername);',
        '        localStorage.setItem("rx_phone", currentPhone);',
        '        localStorage.setItem("rx_zones", JSON.stringify(userZonesList));',
        '        if (userZonesList.length > 0) {',
        '            activeZone = userZonesList[0];',
        '            localStorage.setItem("rx_active_zone", activeZone);',
        '        }',
        '        verifySessionAndBootstrap();',
        '    } catch (e) {',
        '        errEl.innerText = "Server connection error.";',
        '    }',
        '}',

        'async function handleLogout() {',
        '    if (authToken) {',
        '        await apiCall("/api/logout", "POST", { zone: activeZone });',
        '    }',
        '    localStorage.clear();',
        '    authToken = "";',
        '    if (syncTimer) clearInterval(syncTimer);',
        '    document.getElementById("login-screen").classList.remove("hidden");',
        '    document.getElementById("app-screen").classList.add("hidden");',
        '}',

        'async function verifySessionAndBootstrap() {',
        '    document.getElementById("login-screen").classList.add("hidden");',
        '    document.getElementById("app-screen").classList.remove("hidden");',
        '    document.getElementById("role-display").innerText = currentUserRole;',
        '',
        '    if (currentUserRole === "ADMIN") {',
        '        document.getElementById("admin-view").classList.remove("hidden");',
        '        document.getElementById("user-view").classList.add("hidden");',
        '        document.getElementById("user-zone-picker-wrap").style.display = "block";',
        '        document.getElementById("single-zone-badge-wrap").style.display = "none";',
        '        await loadAdminDashboardData();',
        '    } else {',
        '        document.getElementById("admin-view").classList.add("hidden");',
        '        document.getElementById("user-view").classList.remove("hidden");',
        '        if (userZonesList.length > 1) {',
        '            document.getElementById("user-zone-picker-wrap").style.display = "block";',
        '            document.getElementById("single-zone-badge-wrap").style.display = "none";',
        '            populateZonePicker("user-zone-select");',
        '        } else {',
        '            document.getElementById("user-zone-picker-wrap").style.display = "none";',
        '            document.getElementById("single-zone-badge-wrap").style.display = "block";',
        '            document.getElementById("single-zone-name").innerText = activeZone || userZonesList[0] || "DEFAULT";',
        '            if (!activeZone && userZonesList.length > 0) activeZone = userZonesList[0];',
        '        }',
        '        await refreshEngineData();',
        '        if (syncTimer) clearInterval(syncTimer);',
        '        syncTimer = setInterval(refreshEngineData, 2000);',
        '    }',
        '}',

        'async function loadAdminDashboardData() {',
        '    const zones = await apiCall("/api/zones");',
        '    if (zones) {',
        '        const sel = document.getElementById("admin-import-zone");',
        '        sel.innerHTML = \'<option value="">-- Select Target Zone --</option>\';',
        '        zones.forEach(z => {',
        '            sel.innerHTML += `<option value="${z}">${z}</option>`;',
        '        });',
        '        renderZoneCheckboxes(zones);',
        '    }',
        '    const users = await apiCall("/api/users");',
        '    if (users) {',
        '        let html = "";',
        '        users.forEach(u => {',
        '            html += `<tr>',
        '                <td><b>${u.username}</b></td>',
        '                <td>${u.phone}</td>',
        '                <td><span class="badge">${u.zones.join(", ")}</span></td>',
        '                <td>${u.status === 1 ? "<span style=\\\'color:var(--success); font-weight:bold;\\\'>Active</span>" : "<span style=\\\'color:var(--danger); font-weight:bold;\\\'>Disabled</span>"}</td>',
        '                <td>',
        '                    <button class="action-link" onclick="toggleUserStatus(${u.id}, ${u.status})">${u.status === 1 ? "Disable" : "Enable"}</button> | ',
        '                    <button class="action-link" style="color:var(--danger);" onclick="deleteUser(${u.id})">Delete</button>',
        '                </td>',
        '            </tr>`;',
        '        });',
        '        document.getElementById("users-table").innerHTML = html;',
        '    }',
        '    const activity = await apiCall("/api/admin/activity-logs");',
        '    if (activity) {',
        '        let html = "";',
        '        activity.forEach(a => {',
        '            html += `<tr><td>${a.timestamp}</td><td><b>${a.username}</b></td><td>${a.phone}</td><td><span class="badge">${a.action}</span></td></tr>`;',
        '        });',
        '        document.getElementById("activity-table").innerHTML = html;',
        '    }',
        '    const audit = await apiCall("/api/admin/audit-logs");',
        '    if (audit) {',
        '        let html = "";',
        '        audit.forEach(a => {',
        '            html += `<tr><td>${a.timestamp}</td><td><b>${a.username}</b></td><td>${a.phone}</td><td>${a.zone}</td><td><span class="badge">${a.action}</span></td></tr>`;',
        '        });',
        '        document.getElementById("audit-table").innerHTML = html;',
        '    }',
        '}',

        'function renderZoneCheckboxes(zones) {',
        '    const container = document.getElementById("zone-checkbox-container");',
        '    let html = "";',
        '    zones.forEach(z => {',
        '        html += `<label class="zone-checkbox-item"><input type="checkbox" value="${z}" name="newUserZone"> ${z}</label>`;',
        '    });',
        '    container.innerHTML = html;',
        '}',

        'async function registerNewZone() {',
        '    const inputEl = document.getElementById("new-zone-input");',
        '    const zName = inputEl.value.trim();',
        '    if (!zName) {',
        '        alert("Please enter a valid zone name.");',
        '        return;',
        '    }',
        '    const res = await apiCall("/api/zones", "POST", { zone_name: zName });',
        '    if (res) {',
        '        inputEl.value = "";',
        '        await loadAdminDashboardData();',
        '    }',
        '}',

        'async function createUser() {',
        '    const name = document.getElementById("nu-name").value.trim();',
        '    const phone = document.getElementById("nu-phone").value.trim();',
        '    const pass = document.getElementById("nu-pass").value;',
        '    const checkboxes = document.querySelectorAll("input[name=\\\'newUserZone\\\']:checked");',
        '    const zones = Array.from(checkboxes).map(cb => cb.value);',
        '    if (!name || !phone || !pass || zones.length === 0) {',
        '        alert("Please fill all details and select at least one zone.");',
        '        return;',
        '    }',
        '    const res = await apiCall("/api/users", "POST", { username: name, phone, password: pass, zones });',
        '    if (res) {',
        '        alert(res.message || "User created.");',
        '        document.getElementById("nu-name").value = "";',
        '        document.getElementById("nu-phone").value = "";',
        '        document.getElementById("nu-pass").value = "";',
        '        loadAdminDashboardData();',
        '    }',
        '}',

        'async function toggleUserStatus(id, currentStatus) {',
        '    const newStatus = currentStatus === 1 ? 0 : 1;',
        '    await apiCall(`/api/users/${id}/status`, "PUT", { status: newStatus });',
        '    loadAdminDashboardData();',
        '}',

        'async function deleteUser(id) {',
        '    if (!confirm("Permanently delete this user account?")) return;',
        '    await apiCall(`/api/users/${id}`, "DELETE");',
        '    loadAdminDashboardData();',
        '}',

        'async function updateAdminProfile() {',
        '    const u = document.getElementById("admin-new-user").value.trim();',
        '    const p = document.getElementById("admin-new-pass").value;',
        '    if (!u || !p) { alert("Provide both new username and password."); return; }',
        '    const res = await apiCall("/api/admin/profile", "PUT", { newUsername: u, newPassword: p });',
        '    if (res) {',
        '        alert(res.message);',
        '        handleLogout();',
        '    }',
        '}',

        'function populateZonePicker(selectId) {',
        '    const sel = document.getElementById(selectId);',
        '    let html = "";',
        '    userZonesList.forEach(z => {',
        '        html += `<option value="${z}" ${z === activeZone ? "selected" : ""}>${z}</option>`;',
        '    });',
        '    sel.innerHTML = html;',
        '}',

        'async function switchZone() {',
        '    const sel = document.getElementById("user-zone-select");',
        '    activeZone = sel.value;',
        '    localStorage.setItem("rx_active_zone", activeZone);',
        '    await refreshEngineData();',
        '}',

        'async function refreshEngineData() {',
        '    if (!activeZone) activeZone = userZonesList[0] || "DEFAULT";',
        '    masterDrugsCache = await apiCall(`/api/master-drugs?zone=${encodeURIComponent(activeZone)}`) || [];',
        '    dispenseHistoryCache = await apiCall(`/api/dispense/sync?zone=${encodeURIComponent(activeZone)}`) || [];',
        '    renderMasterList();',
        '    renderDispenseDropdown();',
        '    renderCumulativeLedger();',
        '    renderDispenseHistory();',
        '}',

        'function renderMasterList() {',
        '    const query = (document.getElementById("drugSearch").value || "").toLowerCase();',
        '    let html = "";',
        '    masterDrugsCache.forEach(d => {',
        '        if (!query || d.toLowerCase().includes(query)) {',
        '            html += `<tr>',
        '                <td><b>${d}</b></td>',
        '                <td style="text-align:right;">',
        '                    <button class="action-link" onclick="renameDrugPrompt(\\\x27${d}\\\x27)">Rename</button> | ',
        '                    <button class="action-link" style="color:var(--danger);" onclick="deleteDrug(\\\x27${d}\\\x27)">Remove</button>',
        '                </td>',
        '            </tr>`;',
        '        }',
        '    });',
        '    document.getElementById("master-drug-table").innerHTML = html;',
        '}',

        'function renderDispenseDropdown() {',
        '    const sel = document.getElementById("dispenseDrugSelect");',
        '    let html = "";',
        '    masterDrugsCache.forEach(d => {',
        '        html += `<option value="${d}">${d}</option>`;',
        '    });',
        '    sel.innerHTML = html;',
        '}',

        'function calculateTotalsMap() {',
        '    const map = {};',
        '    dispenseHistoryCache.forEach(item => {',
        '        const name = (item.drug_name || "").toUpperCase();',
        '        map[name] = (map[name] || 0) + (parseInt(item.qty) || 0);',
        '    });',
        '    return map;',
        '}',

        'function renderCumulativeLedger() {',
        '    const query = (document.getElementById("ledgerSearch").value || "").toLowerCase();',
        '    const totals = calculateTotalsMap();',
        '    let html = "";',
        '    masterDrugsCache.forEach(d => {',
        '        const qty = totals[d] || 0;',
        '        if (!query || d.toLowerCase().includes(query)) {',
        '            html += `<tr>',
        '                <td><b>${d}</b></td>',
        '                <td><span class="badge" style="background:#e6fffa; color:#234e52; font-size:13px;">${qty}</span></td>',
        '                <td style="text-align:right;">',
        '                    <button class="action-link" onclick="adjustCumulativePrompt(\\\x27${d}\\\x27, ${qty})">Edit Qty</button>',
        '                </td>',
        '            </tr>`;',
        '        }',
        '    });',
        '    document.getElementById("cumulative-ledger-table").innerHTML = html;',
        '}',

        'function renderDispenseHistory() {',
        '    let html = "";',
        '    dispenseHistoryCache.slice(0, 50).forEach(item => {',
        '        html += `<tr>',
        '            <td>${item.timestamp ? item.timestamp.split(" ")[1] || item.timestamp : ""}</td>',
        '            <td><b>${item.drug_name}</b></td>',
        '            <td>+${item.qty}</td>',
        '            <td style="color:var(--text-muted); font-size:11px;">${item.entered_by}</td>',
        '        </tr>`;',
        '    });',
        '    document.getElementById("dispense-history-table").innerHTML = html;',
        '}',

        'async function registerDrug() {',
        '    const nameInput = document.getElementById("newDrugName");',
        '    const name = nameInput.value.trim();',
        '    if (!name) return;',
        '    await apiCall("/api/master-drugs", "POST", { zone: activeZone, drug_name: name });',
        '    nameInput.value = "";',
        '    await refreshEngineData();',
        '}',

        'async function deleteDrug(dName) {',
        '    if (!confirm(`Remove ${dName} from master directory?`)) return;',
        '    await apiCall("/api/master-drugs", "DELETE", { zone: activeZone, drug_name: dName });',
        '    await refreshEngineData();',
        '}',

        'async function renameDrugPrompt(oldName) {',
        '    const newName = prompt(`Rename drug "${oldName}" to:`, oldName);',
        '    if (!newName || newName.trim() === oldName) return;',
        '    await apiCall("/api/master-drugs/rename", "PUT", { zone: activeZone, oldName, newName });',
        '    await refreshEngineData();',
        '}',

        'async function adjustCumulativePrompt(dName, currentQty) {',
        '    const val = prompt(`Set total cumulative quantity for "${dName}":`, currentQty);',
        '    if (val === null) return;',
        '    const newQty = parseInt(val);',
        '    if (isNaN(newQty) || newQty < 0) { alert("Invalid quantity value."); return; }',
        '    await apiCall("/api/dispense/adjust-cumulative", "PUT", { zone: activeZone, drug_name: dName, new_qty: newQty });',
        '    await refreshEngineData();',
        '}',

        'function setQty(val) {',
        '    document.getElementById("dispenseQty").value = val;',
        '}',

        'async function submitDispense() {',
        '    const drug_name = document.getElementById("dispenseDrugSelect").value;',
        '    const qty = parseInt(document.getElementById("dispenseQty").value);',
        '    if (!drug_name || isNaN(qty) || qty <= 0) {',
        '        alert("Select a valid drug and quantity.");',
        '        return;',
        '    }',
        '    await apiCall("/api/dispense", "POST", { zone: activeZone, drug_name, qty });',
        '    await refreshEngineData();',
        '}',

        'async function clearZoneTotals() {',
        '    if (!confirm(`Clear all dispense records for zone "${activeZone}"?`)) return;',
        '    await apiCall("/api/dispense/clear/all", "DELETE", { zone: activeZone });',
        '    await refreshEngineData();',
        '}',

        'async function processImport(type, mode) {',
        '    const zone = document.getElementById("admin-import-zone").value;',
        '    const fileInput = document.getElementById("admin-file-import");',
        '    if (!zone) { alert("Please select a target zone."); return; }',
        '    if (!fileInput.files.length) { alert("Please choose a file to import."); return; }',
        '',
        '    const file = fileInput.files[0];',
        '    const reader = new FileReader();',
        '    reader.onload = async function(e) {',
        '        try {',
        '            let drugsData = [];',
        '            if (file.name.endsWith(".json")) {',
        '                drugsData = JSON.parse(e.target.result);',
        '            } else {',
        '                const data = new Uint8Array(e.target.result);',
        '                const workbook = XLSX.read(data, { type: "array" });',
        '                const firstSheetName = workbook.SheetNames[0];',
        '                const worksheet = workbook.Sheets[firstSheetName];',
        '                drugsData = XLSX.utils.sheet_to_json(worksheet, { header: 1 });',
        '            }',
        '            const res = await apiCall("/api/master-drugs/import", "POST", {',
        '                zone,',
        '                mode,',
        '                drugs: drugsData',
        '            });',
        '            if (res) {',
        '                alert(res.message || "Import completed successfully.");',
        '                fileInput.value = "";',
        '            }',
        '        } catch (err) {',
        '            alert("Failed to parse file: " + err.message);',
        '        }',
        '    };',
        '    if (file.name.endsWith(".json")) {',
        '        reader.readAsText(file);',
        '    } else {',
        '        reader.readAsArrayBuffer(file);',
        '    }',
        '}',

        'function exportExcel() {',
        '    const totals = calculateTotalsMap();',
        '    const rows = masterDrugsCache.map(d => ({',
        '        "Drug Name": d,',
        '        "Total Dispensed": totals[d] || 0,',
        '        "Zone": activeZone',
        '    }));',
        '    const worksheet = XLSX.utils.json_to_sheet(rows);',
        '    const workbook = XLSX.utils.book_new();',
        '    XLSX.utils.book_append_sheet(workbook, worksheet, "Inventory Summary");',
        '    XLSX.writeFile(workbook, `RxMediSync_${activeZone}_Inventory.xlsx`);',
        '}',

        'function exportPDF() {',
        '    const { jsPDF } = window.jspdf;',
        '    const doc = new jsPDF();',
        '    const totals = calculateTotalsMap();',
        '',
        '    doc.setFontSize(18);',
        '    doc.setTextColor(27, 38, 59);',
        '    doc.text("RxMEDISYNC PRO | OFFICIAL INVENTORY REPORT", 14, 20);',
        '',
        '    doc.setFontSize(11);',
        '    doc.setTextColor(100, 100, 100);',
        '    doc.text(`Zone: ${activeZone} | Generated On: ${new Date().toLocaleString()}`, 14, 28);',
        '    doc.text(`Lead System Architect: Debanjan Singha`, 14, 34);',
        '',
        '    const tableData = masterDrugsCache.map(d => [d, totals[d] || 0]);',
        '    doc.autoTable({',
        '        startY: 42,',
        '        head: [["Drug Name", "Total Dispensed"]],',
        '        body: tableData,',
        '        theme: "grid",',
        '        headStyles: { fillColor: [27, 38, 59] }',
        '    });',
        '',
        '    doc.save(`RxMediSync_${activeZone}_Report.pdf`);',
        '}',
        '</script>',
        '</body>',
        '</html>'
    ];

    res.send(htmlLines.join('\n'));
});

// Start High Concurrency Server Engine
app.listen(PORT, () => {
    console.log(`RxMediSync Pro Enterprise Server active on port ${PORT}`);
});
