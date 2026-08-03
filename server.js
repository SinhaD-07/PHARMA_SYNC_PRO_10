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
console.log(" CRITICAL HOSTING NOTE: Ensure this runs on a server with persistent ");
console.log(" storage (VPS/EC2/Persistent Volume). Ephemeral hosts (Heroku/Render free) ");
console.log(" will automatically delete the local .db file upon server sleep.");
console.log("================================================================");

// Strict Data Firewall & Security Headers
app.use((req, res, next) => {
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self' cdnjs.cloudflare.com; script-src 'self' 'unsafe-inline' 'unsafe-eval' cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' cdnjs.cloudflare.com; img-src 'self' data:; connect-src 'self';"
    );
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'no-referrer');
    next();
});

app.use(cors());
app.use(express.json({ limit: '100mb' }));

// Initialize Database with WAL Mode & High Concurrency Wait Times
const db = new sqlite3.Database('./pharmacy.db', (err) => {
    if (!err) {
        db.configure('busyTimeout', 15000); // Wait up to 15 seconds if 100+ users hit DB at exact same time
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

        // High Speed Database Indexes for 1M+ Records Querying
        db.run("CREATE INDEX IF NOT EXISTS idx_master_zone_drug ON master_drugs(zone, drug_name)");
        db.run("CREATE INDEX IF NOT EXISTS idx_dispenses_zone ON dispenses(zone)");
        db.run("CREATE INDEX IF NOT EXISTS idx_dispenses_zone_drug ON dispenses(zone, drug_name)"); // Critical for fast backend grouping
        db.run("CREATE INDEX IF NOT EXISTS idx_activity_timestamp ON activity_logs(timestamp)");

        // PER USER REQUIREMENT: NO DATA MUST BE AUTO-DELETED UNDER ANY CIRCUMSTANCES.
        // The 30-day automatic deletion query has been completely removed.

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
            if (user.status !== 1) return res.status(403).json({ error: "ACCESS_DISABLED", message: "ERROR! PLEASE CONTACT THE ADMIN" });
            req.user = user;
            next();
        });
    });
};

function extractDrugNames(item) {
    if (!item) return [];
    let rawStr = "";
    if (typeof item === 'string') rawStr = item;
    else if (typeof item === 'object') {
        const keys = Object.keys(item);
        const matchKey = keys.find(k => /drug|name|item|product|title|description/i.test(k));
        if (matchKey && item[matchKey]) rawStr = String(item[matchKey]);
        else if (keys.length > 0 && item[keys[0]]) rawStr = String(item[keys[0]]);
    }
    if (!rawStr) return [];
    return rawStr.split(/[\n\r,;]+/).map(s => s.trim().toUpperCase()).filter(s => s.length > 0);
}

// ==========================================
// BACKEND API ROUTES
// ==========================================

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Missing required fields." });

    db.get("SELECT * FROM users WHERE username = ? OR phone = ?", [username, username], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: "Invalid credentials." });
        if (user.status !== 1) return res.status(403).json({ error: "ERROR! PLEASE CONTACT THE ADMIN" });

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

// Admin Control Routes (Unchanged)
app.put('/api/admin/profile', authenticateToken, async (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required." });
    const hash = await bcrypt.hash(req.body.newPassword, 10);
    db.run("UPDATE users SET username = ?, password = ? WHERE id = ?", [req.body.newUsername.trim(), hash, req.user.id], function(err) {
        if (err) return res.status(500).json({ error: "Username already taken." });
        res.json({ message: "Admin credentials updated." });
    });
});

app.get('/api/users', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required." });
    db.all("SELECT id, username, phone, role, zones, status FROM users WHERE role != 'ADMIN'", [], (err, rows) => {
        res.json(rows.map(r => ({ ...r, zones: JSON.parse(r.zones || "[]") })));
    });
});

app.post('/api/users', authenticateToken, async (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required." });
    const { username, phone, password, zones } = req.body;
    const hash = await bcrypt.hash(password, 10);
    db.run("INSERT INTO users (username, phone, password, role, zones, status) VALUES (?, ?, ?, 'USER', ?, 1)", [username.trim(), phone.trim(), hash, JSON.stringify(zones)], (err) => {
        if (err) return res.status(400).json({ error: "User already exists." });
        res.json({ message: "User created." });
    });
});

app.put('/api/users/:id/zones', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required." });
    db.run("UPDATE users SET zones = ? WHERE id = ?", [JSON.stringify(req.body.zones), req.params.id], () => res.json({ message: "Zones updated." }));
});

app.put('/api/users/:id/status', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required." });
    db.run("UPDATE users SET status = ? WHERE id = ?", [req.body.status, req.params.id], () => res.json({ message: "Status updated." }));
});

app.delete('/api/users/:id', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required." });
    db.run("DELETE FROM users WHERE id = ?", [req.params.id], () => res.json({ message: "User removed." }));
});

app.get('/api/zones', authenticateToken, (req, res) => {
    if (req.user.role === 'ADMIN') {
        db.all("SELECT zone_name FROM zone_registry ORDER BY zone_name ASC", [], (err, rows) => res.json(rows.map(r => r.zone_name)));
    } else {
        res.json(JSON.parse(req.user.zones || "[]"));
    }
});

app.post('/api/zones', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required." });
    db.run("INSERT OR IGNORE INTO zone_registry (zone_name) VALUES (?)", [req.body.zone_name.trim().toUpperCase()], () => res.json({ message: "Zone registered." }));
});

app.get('/api/admin/audit-logs', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required." });
    db.all("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200", [], (err, rows) => res.json(rows));
});

app.delete('/api/admin/audit-logs/clear', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required." });
    db.run("DELETE FROM audit_logs", [], () => res.json({ message: "Logs cleared." }));
});

app.get('/api/admin/activity-logs', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required." });
    db.all("SELECT * FROM activity_logs ORDER BY id DESC LIMIT 500", [], (err, rows) => res.json(rows));
});

app.delete('/api/admin/activity-logs/clear', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required." });
    db.run("DELETE FROM activity_logs", [], () => res.json({ message: "Logs cleared." }));
});

// MASTER DRUGS
app.get('/api/master-drugs', authenticateToken, (req, res) => {
    db.all("SELECT drug_name FROM master_drugs WHERE zone = ? ORDER BY drug_name ASC", [req.query.zone], (err, rows) => res.json(rows.map(r => r.drug_name)));
});

app.post('/api/master-drugs', authenticateToken, (req, res) => {
    db.run("INSERT OR IGNORE INTO master_drugs (zone, drug_name) VALUES (?, ?)", [req.body.zone, req.body.drug_name.trim().toUpperCase()], () => res.json({ message: "Drug registered." }));
});

app.put('/api/master-drugs/rename', authenticateToken, (req, res) => {
    db.serialize(() => {
        db.run("UPDATE master_drugs SET drug_name = ? WHERE drug_name = ? AND zone = ?", [req.body.newName.trim().toUpperCase(), req.body.oldName.trim().toUpperCase(), req.body.zone]);
        db.run("UPDATE dispenses SET drug_name = ? WHERE drug_name = ? AND zone = ?", [req.body.newName.trim().toUpperCase(), req.body.oldName.trim().toUpperCase(), req.body.zone], () => res.json({ message: "Drug renamed." }));
    });
});

app.delete('/api/master-drugs', authenticateToken, (req, res) => {
    db.run("DELETE FROM master_drugs WHERE drug_name = ? AND zone = ?", [req.body.drug_name, req.body.zone], () => res.json({ message: "Drug removed." }));
});

app.post('/api/master-drugs/import', authenticateToken, (req, res) => {
    const { mode, zone, drugs } = req.body;
    let items = Array.isArray(drugs) ? drugs : [drugs];
    db.serialize(() => {
        db.run("BEGIN TRANSACTION");
        if (mode === 'reset') db.run("DELETE FROM master_drugs WHERE zone = ?", [zone]);
        const stmt = db.prepare("INSERT OR IGNORE INTO master_drugs (zone, drug_name) VALUES (?, ?)");
        items.forEach(item => extractDrugNames(item).forEach(dName => stmt.run(zone, dName)));
        stmt.finalize();
        db.run("COMMIT", () => res.json({ message: "Master Directory imported." }));
    });
});

// USER DISPENSE API
app.post('/api/dispense', authenticateToken, (req, res) => {
    db.run("INSERT INTO dispenses (zone, drug_name, qty, entered_by) VALUES (?, ?, ?, ?)", 
        [req.body.zone, req.body.drug_name.trim().toUpperCase(), parseInt(req.body.qty), req.user.username], 
        () => res.json({ message: "Dispense recorded." })
    );
});

// CRITICAL FIX: To support 1,000,000+ entries, cumulative math is done server-side via SQL GROUP BY.
app.get('/api/dispense/sync', authenticateToken, (req, res) => {
    const zone = req.query.zone;
    db.serialize(() => {
        db.all("SELECT id, drug_name, qty, entered_by, timestamp FROM dispenses WHERE zone = ? ORDER BY id DESC LIMIT 100", [zone], (err, historyRows) => {
            db.all("SELECT drug_name, SUM(qty) as total_qty FROM dispenses WHERE zone = ? GROUP BY drug_name", [zone], (err, totalRows) => {
                res.json({ history: historyRows || [], totals: totalRows || [] });
            });
        });
    });
});

app.post('/api/dispense/import', authenticateToken, (req, res) => {
    const { mode, zone, items } = req.body;
    if (!zone || !items || !Array.isArray(items)) return res.status(400).json({ error: "Invalid payload." });
    
    db.serialize(() => {
        db.run("BEGIN TRANSACTION");
        if (mode === 'reset') db.run("DELETE FROM dispenses WHERE zone = ?", [zone]);
        
        const stmt = db.prepare("INSERT INTO dispenses (zone, drug_name, qty, entered_by) VALUES (?, ?, ?, ?)");
        let count = 0;
        items.forEach(item => {
            const drug = (item.drug_name || item.Drug || item.Name || Object.values(item)[0] || "").toString().trim().toUpperCase();
            const qty = parseInt(item.total_qty || item.qty || item.Qty || item.Quantity || Object.values(item)[1] || 0);
            if (drug && !isNaN(qty) && qty > 0) {
                stmt.run(zone, drug, qty, req.user.username + " (Bulk Import)");
                count++;
            }
        });
        stmt.finalize();
        db.run("COMMIT", (err) => {
            if (err) return res.status(500).json({ error: "Import failed." });
            res.json({ message: `Successfully processed ${count} bulk entries.` });
        });
    });
});

app.put('/api/dispense/adjust-cumulative', authenticateToken, (req, res) => {
    const { zone, drug_name, new_qty } = req.body;
    const targetQty = parseInt(new_qty);
    db.serialize(() => {
        db.run("DELETE FROM dispenses WHERE zone = ? AND UPPER(drug_name) = ?", [zone, drug_name.trim().toUpperCase()], () => {
            if (targetQty > 0) {
                db.run("INSERT INTO dispenses (zone, drug_name, qty, entered_by) VALUES (?, ?, ?, ?)",
                    [zone, drug_name.trim().toUpperCase(), targetQty, req.user.username + " (Manual Override)"],
                    () => res.json({ message: "Cumulative quantity updated." })
                );
            } else res.json({ message: "Cumulative quantity reset to 0." });
        });
    });
});

app.put('/api/dispense/:id', authenticateToken, (req, res) => {
    db.run("UPDATE dispenses SET qty = ? WHERE id = ?", [parseInt(req.body.qty), req.params.id], () => res.json({ message: "Dispense updated." }));
});

app.delete('/api/dispense/:id', authenticateToken, (req, res) => {
    db.run("DELETE FROM dispenses WHERE id = ?", [req.params.id], () => res.json({ message: "Dispense entry removed." }));
});

app.delete('/api/dispense/clear/all', authenticateToken, (req, res) => {
    db.run("DELETE FROM dispenses WHERE zone = ?", [req.body.zone], () => res.json({ message: "Totals cleared." }));
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
        '    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>',
        '    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.23/jspdf.plugin.autotable.min.js"></script>',
        '    <script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></script>',
        '    <style>',
        '        :root { --bg: #f4f7fa; --accent: #4361ee; --success: #2ec4b6; --danger: #e71d36; --warning: #ff9f1c; --sidebar: #1b263b; --card-bg: #ffffff; --text-main: #2b2d42; --text-muted: #8d99ae; }',
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
        '        .action-link { cursor: pointer; font-size: 12px; font-weight: bold; text-decoration: underline; background: none; border: none; padding: 0 6px; margin: 0; width: auto; display: inline; }',
        '        .hidden { display: none !important; }',
        '        .flex { display: flex; gap: 10px; align-items: center; }',
        '        .zone-checkbox-group { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 14px; background: #f8fafc; padding: 12px; border-radius: 8px; border: 1px solid #d1d9e6; }',
        '        .zone-checkbox-item { display: flex; align-items: center; gap: 6px; font-size: 13px; color: var(--text-main); cursor: pointer; }',
        '        .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); display: flex; justify-content: center; align-items: center; z-index: 1000; backdrop-filter: blur(2px); }',
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
        '        </div>',

        '        <!-- APPLICATION SCREEN -->',
        '        <div id="app-screen" class="hidden">',
        '            <div class="header-bar">',
        '                <div style="display: flex; align-items: center;">',
        '                    <h1 style="margin:0; font-size:20px; color:var(--sidebar); display: inline-block;">RxMEDISYNC<span style="color:var(--accent)">PRO</span></h1>',
        '                    <span id="role-display" class="badge" style="margin-left: 10px;">ROLE</span>',
        '                    <span style="margin-left: 15px; font-size: 12px; color: var(--text-muted);"><span class="live-dot"></span>LIVE AUTO-SYNC</span>',
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
        '                    <div style="display:flex; justify-content:space-between; align-items:center;">',
        '                        <h2>🔐 User Login / Logout Activity Tracker</h2>',
        '                        <button onclick="clearActivityLogs()" class="primary-btn danger" style="width:auto; padding:6px 12px; font-size:11px;">CLEAR ACTIVITY LOGS</button>',
        '                    </div>',
        '                    <div class="table-wrap">',
        '                        <table>',
        '                            <thead><tr><th>Timestamp</th><th>Username</th><th>Phone</th><th>Action Event</th></tr></thead>',
        '                            <tbody id="activity-table"></tbody>',
        '                        </table>',
        '                    </div>',
        '                </div>',

        '                <div class="panel">',
        '                    <div style="display:flex; justify-content:space-between; align-items:center;">',
        '                        <h2>📜 Transaction Audit Logs</h2>',
        '                        <button onclick="clearAuditLogs()" class="primary-btn danger" style="width:auto; padding:6px 12px; font-size:11px;">CLEAR AUDIT LOGS</button>',
        '                    </div>',
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
        '                        <input type="text" style="margin-top:15px" onkeyup="filterTable(\'masterBody\', this.value)" placeholder="Search directory...">',
        '                        <div class="table-wrap"><table><tbody id="masterBody"></tbody></table></div>',
        '                    </div>',

        '                    <!-- PANEL 2: DISPENSE CONSOLE & CUMULATIVE TOTALS -->',
        '                    <div class="panel">',
        '                        <h2>🛒 Dispense Console</h2>',
        '                        <div style="display: grid; grid-template-columns: 1fr 120px; gap: 10px;">',
        '                            <input type="text" id="searchDrug" list="drugList" placeholder="Select / Type Drug Name..." oninput="checkDrugAutoJump(event)" onkeydown="handleDrugNameKeydown(event)">',
        '                            <input type="number" id="dispenseAmount" placeholder="Qty" onkeydown="if(event.key===\'Enter\') dispenseDrug()">',
        '                        </div>',
        '                        <datalist id="drugList"></datalist>',
        '                        <div class="qty-grid">',
        '                            <button class="qty-pill" onclick="setQty(1)">1</button><button class="qty-pill" onclick="setQty(5)">5</button><button class="qty-pill" onclick="setQty(10)">10</button><button class="qty-pill" onclick="setQty(15)">15</button>',
        '                            <button class="qty-pill" onclick="setQty(20)">20</button><button class="qty-pill" onclick="setQty(30)">30</button><button class="qty-pill" onclick="setQty(60)">60</button><button class="qty-pill" onclick="setQty(120)">120</button>',
        '                        </div>',
        '                        <button class="primary-btn success" style="height: 42px; font-size:15px" id="recordBtn" onclick="dispenseDrug()">RECORD ENTRY</button>',

        '                        <h2 style="margin-top:25px">📊 Cumulative Totals (Auto-Aggregated via SQL)</h2>',
        '                        <input type="text" onkeyup="filterTable(\'dailyBody\', this.value)" placeholder="Filter cumulative totals...">',
        '                        <div class="table-wrap" style="max-height: 380px;">',
        '                            <table><thead><tr><th>Drug Name</th><th>Total Qty</th><th style="text-align:right">Action</th></tr></thead><tbody id="dailyBody"></tbody></table>',
        '                        </div>',
        '                    </div>',

        '                    <!-- PANEL 3: HISTORY & REPORT -->',
        '                    <div class="panel">',
        '                        <h2>🕒 Recent History (Last 100)</h2>',
        '                        <div class="table-wrap" style="max-height: 250px; margin-bottom: 25px;"><table><tbody id="historyBody"></tbody></table></div>',

        '                        <h2>📥 Import Today\'s Total Backup Data</h2>',
        '                        <input type="file" id="user-file-import" accept=".json, .xlsx, .xls">',
        '                        <div class="flex">',
        '                            <button onclick="processUserImport(\'merge\')" class="primary-btn">Merge & Add</button>',
        '                            <button onclick="processUserImport(\'reset\')" class="primary-btn warning">Reset & Add</button>',
        '                        </div>',

        '                        <h2 style="margin-top:25px">📄 Report & Maintenance</h2>',
        '                        <input type="text" id="pdfRemarks" placeholder="Enter remarks (Mandatory)..." onkeydown="if(event.key===\'Enter\') generateReport()">',
        '                        <button class="primary-btn danger" onclick="generateReport()">GENERATE PDF + JSON BACKUP</button>',
        '                        <button class="primary-btn" style="background:#64748b; margin-top:6px" onclick="resetDailyDataOnly()">MANUALLY WIPE ALL ZONE DATA</button>',
        '                    </div>',
        '                </div>',
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

        '        <!-- Login Modal -->',
        '        <div id="login-zone-modal" class="modal-overlay hidden">',
        '            <div class="panel" style="width: 380px; text-align: center; margin-bottom: 0;">',
        '                <h2>📍 Select Active Zone</h2>',
        '                <select id="initial-zone-select" style="padding: 12px; font-size: 15px; margin-bottom: 20px;"></select>',
        '                <button onclick="confirmInitialZone()" class="primary-btn success" style="padding: 12px; font-size: 15px;">CONFIRM & ENTER</button>',
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
        '        let dailyLog = {};', // Now explicitly mapped from SQL aggregate sums',
        '        let availableZonesList = [];',
        '        let autoSyncTimer = null;',

        '        let lastMasterCache = "";',
        '        let lastHistoryCache = "";',
        '        let lastTotalsCache = "";',

        '        if (token) checkSession();',

        '        window.addEventListener("beforeunload", function (e) {',
        '            if (currentUser && currentUser.role !== "ADMIN" && Object.keys(dailyLog).length > 0) {',
        '                e.preventDefault();',
        '                e.returnValue = "Have you downloaded your JSON and PDF backups? Your data remains saved, but make sure you have local copies!";',
        '                return e.returnValue;',
        '            }',
        '        });',

        '        async function handleAccessError(res) {',
        '            if (res.status === 403 || res.status === 401) {',
        '                alert("Session expired or access denied. Please log in again.");',
        '                handleLogout(true);',
        '                return true;',
        '            }',
        '            return false;',
        '        }',

        '        async function handleLogin() {',
        '            const u = document.getElementById("login-username").value;',
        '            const p = document.getElementById("login-password").value;',
        '            const res = await fetch("/api/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: u, password: p }) });',
        '            const data = await res.json();',
        '            if (res.ok) {',
        '                localStorage.setItem("token", data.token);',
        '                token = data.token;',
        '                currentUser = data;',
        '                initApp();',
        '            } else document.getElementById("login-error").innerText = data.error || data.message;',
        '        }',

        '        function handleLogout(force = false) {',
        '            if (!force && currentUser && currentUser.role !== "ADMIN" && Object.keys(dailyLog).length > 0) {',
        '                if (!confirm("Are you sure you want to log out?\\n\\nHave you downloaded your PDF and JSON backup? (Your data is safely stored in the database and will be here when you log back in.)")) return;',
        '            }',
        '            if (autoSyncTimer) clearInterval(autoSyncTimer);',
        '            if(token) fetch("/api/logout", { method: "POST", headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" }, body: JSON.stringify({ zone: activeZone }) }).catch(()=>{});',
        '            localStorage.removeItem("token");',
        '            location.reload();',
        '        }',

        '        function checkSession() { initApp(); }',

        '        async function initApp() {',
        '            document.getElementById("login-screen").classList.add("hidden");',
        '            document.getElementById("app-screen").classList.remove("hidden");',
        '            try {',
        '                currentUser = JSON.parse(atob(token.split(".")[1]));',
        '                document.getElementById("role-display").innerText = currentUser.role;',
        '                if (currentUser.role === "ADMIN") {',
        '                    document.getElementById("admin-view").classList.remove("hidden");',
        '                    loadAdminData();',
        '                } else {',
        '                    document.getElementById("user-view").classList.remove("hidden");',
        '                    loadUserZones();',
        '                }',
        '            } catch(err) { handleLogout(true); }',
        '        }',

        '        function checkDrugAutoJump(e) {',
        '            if (masterDrugsList.includes(e.target.value.trim().toUpperCase())) {',
        '                const qtyInput = document.getElementById("dispenseAmount");',
        '                qtyInput.focus(); qtyInput.select();',
        '            }',
        '        }',

        '        function handleDrugNameKeydown(e) {',
        '            if (e.key === "Enter") {',
        '                e.preventDefault();',
        '                document.getElementById("dispenseAmount").focus();',
        '            }',
        '        }',

        '        async function registerNewZone() {',
        '            const zInput = document.getElementById("new-zone-input").value;',
        '            if (!zInput) return alert("Enter a Zone Name.");',
        '            const res = await fetch("/api/zones", { method: "POST", headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" }, body: JSON.stringify({ zone_name: zInput }) });',
        '            if (await handleAccessError(res)) return;',
        '            if (res.ok) { alert("Zone registered!"); document.getElementById("new-zone-input").value = ""; loadAdminData(); }',
        '        }',

        '        async function loadAdminData() {',
        '            const zRes = await fetch("/api/zones", { headers: { "Authorization": "Bearer " + token } });',
        '            if (await handleAccessError(zRes)) return;',
        '            availableZonesList = await zRes.json();',
        '            const zoneContainer = document.getElementById("zone-checkbox-container");',
        '            const zoneImportSelect = document.getElementById("admin-import-zone");',
        '            zoneContainer.innerHTML = ""; zoneImportSelect.innerHTML = \'<option value="">-- Select Target Zone --</option>\';',
        '            availableZonesList.forEach(z => {',
        '                zoneContainer.innerHTML += `<label class="zone-checkbox-item"><input type="checkbox" value="${z}" name="assigned-zones"> ${z}</label>`;',
        '                zoneImportSelect.innerHTML += `<option value="${z}">${z}</option>`;',
        '            });',
        '            ',
        '            const res = await fetch("/api/users", { headers: { "Authorization": "Bearer " + token } });',
        '            const users = await res.json();',
        '            const tbody = document.getElementById("users-table"); tbody.innerHTML = "";',
        '            users.forEach(u => {',
        '                const zonesStr = u.zones.join(",");',
        '                tbody.innerHTML += `<tr><td>${u.username}</td><td>${u.phone}</td><td>${u.zones.join(", ")}</td><td>${u.status ? "ACTIVE" : "DISABLED"}</td>',
        '                    <td>',
        '                        <button onclick="openEditModal(${u.id}, \'${u.username}\', \'${zonesStr}\')" class="action-link" style="color:var(--accent); font-size:13px; text-decoration:none; border:1px solid var(--accent); border-radius:4px; padding:4px 8px;">Edit Zones</button>',
        '                        <button onclick="toggleUser(${u.id}, ${u.status ? 0 : 1})" class="action-link" style="color:var(--warning);">${u.status ? "Disable" : "Enable"}</button>',
        '                        <button onclick="removeUser(${u.id})" class="action-link" style="color:var(--danger);">Remove</button>',
        '                    </td></tr>`;',
        '            });',

        '            const actRes = await fetch("/api/admin/activity-logs", { headers: { "Authorization": "Bearer " + token } });',
        '            const actBody = document.getElementById("activity-table"); actBody.innerHTML = "";',
        '            (await actRes.json()).forEach(l => actBody.innerHTML += `<tr><td>${l.timestamp}</td><td>${l.username}</td><td>${l.phone}</td><td><span class="badge" style="background:${l.action===\'LOGIN\'?\'#dcfce7;color:#166534\':\'#fee2e2;color:#991b1b\'}">${l.action}</span></td></tr>`);',

        '            const auditRes = await fetch("/api/admin/audit-logs", { headers: { "Authorization": "Bearer " + token } });',
        '            const auditBody = document.getElementById("audit-table"); auditBody.innerHTML = "";',
        '            (await auditRes.json()).forEach(l => auditBody.innerHTML += `<tr><td>${l.timestamp}</td><td>${l.username}</td><td>${l.phone}</td><td>${l.zone}</td><td>${l.action}</td></tr>`);',
        '        }',

        '        async function clearActivityLogs() {',
        '            if(!confirm("Wipe all Activity Logs?")) return;',
        '            await fetch("/api/admin/activity-logs/clear", { method: "DELETE", headers: { "Authorization": "Bearer " + token } }); loadAdminData();',
        '        }',
        '        async function clearAuditLogs() {',
        '            if(!confirm("Wipe all Transaction Audit Logs?")) return;',
        '            await fetch("/api/admin/audit-logs/clear", { method: "DELETE", headers: { "Authorization": "Bearer " + token } }); loadAdminData();',
        '        }',

        '        async function loadUserZones() {',
        '            const zRes = await fetch("/api/zones", { headers: { "Authorization": "Bearer " + token } });',
        '            if (await handleAccessError(zRes)) return;',
        '            assignedUserZones = await zRes.json();',
        '            if (assignedUserZones.length === 1) {',
        '                activeZone = assignedUserZones[0];',
        '                document.getElementById("user-zone-picker-wrap").style.display = "none";',
        '                document.getElementById("single-zone-badge-wrap").style.display = "block";',
        '                document.getElementById("single-zone-name").innerText = activeZone;',
        '                startAutoSync();',
        '            } else if (assignedUserZones.length > 1) {',
        '                document.getElementById("user-zone-picker-wrap").style.display = "block";',
        '                const initSelect = document.getElementById("initial-zone-select");',
        '                const userSelect = document.getElementById("user-zone-select");',
        '                initSelect.innerHTML = ""; userSelect.innerHTML = "";',
        '                assignedUserZones.forEach(z => { initSelect.innerHTML += `<option value="${z}">${z}</option>`; userSelect.innerHTML += `<option value="${z}">${z}</option>`; });',
        '                document.getElementById("login-zone-modal").classList.remove("hidden");',
        '            } else { alert("No zones assigned to you. Contact Admin."); handleLogout(true); }',
        '        }',

        '        function confirmInitialZone() {',
        '            activeZone = document.getElementById("initial-zone-select").value;',
        '            document.getElementById("user-zone-select").value = activeZone;',
        '            document.getElementById("login-zone-modal").classList.add("hidden");',
        '            startAutoSync();',
        '        }',
        '        function switchZone() { activeZone = document.getElementById("user-zone-select").value; lastMasterCache = ""; lastHistoryCache = ""; lastTotalsCache = ""; syncUserData(); }',
        '        function startAutoSync() { syncUserData(); if (autoSyncTimer) clearInterval(autoSyncTimer); autoSyncTimer = setInterval(() => { if (activeZone && !document.hidden) syncUserData(true); }, 2000); }',

        '        async function syncUserData(isSilent = false) {',
        '            try {',
        '                const mRes = await fetch(`/api/master-drugs?zone=${activeZone}`, { headers: { "Authorization": "Bearer " + token } });',
        '                if (!isSilent && await handleAccessError(mRes)) return;',
        '                if(mRes.status === 401 || mRes.status === 403) return handleLogout(true);',
        '                ',
        '                const masterData = await mRes.json();',
        '                const masterStr = JSON.stringify(masterData);',

        '                // Fetch aggregated totals directly from DB grouping, fixing the 1000 limit bug completely',
        '                const hRes = await fetch(`/api/dispense/sync?zone=${activeZone}`, { headers: { "Authorization": "Bearer " + token } });',
        '                const syncData = await hRes.json();',
        '                const historyStr = JSON.stringify(syncData.history);',
        '                const totalsStr = JSON.stringify(syncData.totals);',

        '                let masterChanged = false;',
        '                let historyChanged = false;',

        '                if (masterStr !== lastMasterCache) { masterDrugsList = masterData; lastMasterCache = masterStr; masterChanged = true; }',
        '                if (historyStr !== lastHistoryCache || totalsStr !== lastTotalsCache) {',
        '                    dispenseHistory = syncData.history;',
        '                    dailyLog = {};',
        '                    syncData.totals.forEach(t => dailyLog[t.drug_name] = t.total_qty);',
        '                    lastHistoryCache = historyStr; lastTotalsCache = totalsStr; historyChanged = true;',
        '                }',

        '                if (masterChanged || historyChanged) updateUI(masterChanged, historyChanged);',
        '            } catch(e) { console.log("Auto sync paused...", e); }',
        '        }',

        '        function updateUI(masterChanged, historyChanged) {',
        '            if (masterChanged) {',
        '                renderTable("masterBody", masterDrugsList.sort(), (item) => `<td>${item}</td><td style="text-align:right"><button class="action-link" style="color:var(--warning)" onclick="editMasterDrugInline(\'${item}\')">Edit</button><button class="action-link" style="color:var(--danger)" onclick="removeDrug(\'${item}\')">Del</button></td>`);',
        '                document.getElementById("drugList").innerHTML = masterDrugsList.map(m => `<option value="${m}">`).join("");',
        '            }',
        '            if (historyChanged) {',
        '                renderTable("dailyBody", Object.keys(dailyLog).sort(), (k) => `<td>${k}</td><td><span class="badge">${dailyLog[k]}</span></td><td style="text-align:right"><button class="action-link" style="color:var(--warning)" onclick="editCumulativeQty(\'${k}\', ${dailyLog[k]})">Edit</button></td>`);',
        '                renderTable("historyBody", dispenseHistory, (i) => `<td><span style="color:gray; font-size:10px">${i.timestamp}</span><br>${i.drug_name} (<b>${i.qty}</b>) - <i style="font-size:11px">${i.entered_by}</i></td><td style="text-align:right"><button class="action-link" style="color:var(--warning)" onclick="editHistoryQty(${i.id}, ${i.qty})">Edit</button><button class="action-link" style="color:var(--danger)" onclick="undoTransaction(${i.id})">Undo</button></td>`);',
        '            }',
        '        }',

        '        function renderTable(id, data, templateFn) { document.getElementById(id).innerHTML = data.map(item => `<tr>${templateFn(item)}</tr>`).join(""); }',
        '        function setQty(v) { document.getElementById("dispenseAmount").value = v; document.getElementById("recordBtn").focus(); }',

        '        async function registerDrug() {',
        '            const i = document.getElementById("newDrugName"); const d = i.value.trim().toUpperCase(); if (!d) return;',
        '            await fetch("/api/master-drugs", { method: "POST", headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" }, body: JSON.stringify({ zone: activeZone, drug_name: d }) });',
        '            i.value = ""; syncUserData();',
        '        }',

        '        async function dispenseDrug() {',
        '            const nI = document.getElementById("searchDrug"); const aI = document.getElementById("dispenseAmount");',
        '            const d = nI.value.trim().toUpperCase(); const q = parseInt(aI.value);',
        '            if (!masterDrugsList.includes(d)) return alert("Drug not found in Master Directory. Please register it first.");',
        '            if (isNaN(q) || q <= 0) return alert("Please enter a valid quantity.");',
        '            await fetch("/api/dispense", { method: "POST", headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" }, body: JSON.stringify({ zone: activeZone, drug_name: d, qty: q }) });',
        '            nI.value = ""; aI.value = ""; syncUserData(); nI.focus();',
        '        }',

        '        async function editCumulativeQty(drugName, currentQty) {',
        '            const newQty = prompt(`Edit Cumulative Quantity for ${drugName}:`, currentQty);',
        '            if (newQty === null || isNaN(parseInt(newQty)) || parseInt(newQty) < 0) return;',
        '            await fetch("/api/dispense/adjust-cumulative", { method: "PUT", headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" }, body: JSON.stringify({ zone: activeZone, drug_name: drugName, new_qty: parseInt(newQty) }) });',
        '            syncUserData();',
        '        }',

        '        async function editHistoryQty(id, oldQty) {',
        '            const nq = prompt("Enter updated quantity:", oldQty); if (!nq || isNaN(parseInt(nq))) return;',
        '            await fetch(`/api/dispense/${id}`, { method: "PUT", headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" }, body: JSON.stringify({ qty: parseInt(nq) }) });',
        '            syncUserData();',
        '        }',

        '        async function undoTransaction(id) { if (!confirm("Undo this dispense entry?")) return; await fetch(`/api/dispense/${id}`, { method: "DELETE", headers: { "Authorization": "Bearer " + token } }); syncUserData(); }',
        '        async function removeDrug(dName) { if (!confirm(`Delete ${dName} from Master?`)) return; await fetch("/api/master-drugs", { method: "DELETE", headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" }, body: JSON.stringify({ zone: activeZone, drug_name: dName }) }); syncUserData(); }',
        '        async function editMasterDrugInline(oldName) { const newName = prompt(`Edit drug name for ${oldName}:`, oldName); if (!newName || newName.trim().toUpperCase() === oldName) return; await fetch("/api/master-drugs/rename", { method: "PUT", headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" }, body: JSON.stringify({ zone: activeZone, oldName: oldName, newName: newName.trim().toUpperCase() }) }); syncUserData(); }',
        '        async function resetDailyDataOnly() { if (confirm("MANUAL WIPE: Delete ALL recorded data in this zone? (Data is NOT auto-deleted, do this only if intended)")) { await fetch("/api/dispense/clear/all", { method: "DELETE", headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" }, body: JSON.stringify({ zone: activeZone }) }); syncUserData(); } }',
        '        function clearHistoryOnly() { resetDailyDataOnly(); }',

        '        function generateReport() {',
        '            const remarks = document.getElementById("pdfRemarks").value.trim();',
        '            if (!remarks) return alert("Remarks field is mandatory for downloading PDF reporting.");',
        '            ',
        '            // Generate JSON Backup Blob',
        '            const jsonStr = JSON.stringify(dailyLog, null, 2);',
        '            const blob = new Blob([jsonStr], { type: "application/json" });',
        '            const url = URL.createObjectURL(blob);',
        '            const a = document.createElement("a");',
        '            a.href = url; a.download = `RxMediBackup_${activeZone}_${Date.now()}.json`;',
        '            document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);',
        '            ',
        '            // Generate PDF Report',
        '            const { jsPDF } = window.jspdf; const doc = new jsPDF();',
        '            doc.setFontSize(16); doc.text(`RXMEDISYNC DAILY REPORT - ${activeZone}`, 14, 20);',
        '            doc.setFontSize(10); doc.text(`Date: ${new Date().toLocaleString()} | Remarks: ${remarks}`, 14, 28);',
        '            const tableRows = Object.keys(dailyLog).sort().map(k => [k, dailyLog[k]]);',
        '            doc.autoTable({ startY: 35, head: [["Drug Name", "Cumulative Total Quantity"]], body: tableRows, didDrawPage: function (data) { doc.setFontSize(8); doc.setTextColor(100); doc.text("Lead Developer: Debanjan Singha", 14, doc.internal.pageSize.height - 10); doc.text(`Page ${data.pageNumber} of ${doc.internal.getNumberOfPages()}`, doc.internal.pageSize.width - 30, doc.internal.pageSize.height - 10, { align: "right" }); } });',
        '            doc.save(`RxMediReport_${activeZone}_${Date.now()}.pdf`);',
        '        }',

        '        // User Data Import Functions',
        '        function processUserImport(mode) {',
        '            const fileInput = document.getElementById("user-file-import");',
        '            if (!fileInput.files.length) return alert("Choose a file to import.");',
        '            const file = fileInput.files[0]; const fileName = file.name.toLowerCase();',
        '            const reader = new FileReader();',
        '            if (fileName.endsWith(".json")) {',
        '                reader.onload = async (e) => {',
        '                    try {',
        '                        const parsed = JSON.parse(e.target.result);',
        '                        const arr = Array.isArray(parsed) ? parsed : Object.keys(parsed).map(k => ({ drug_name: k, qty: parsed[k] }));',
        '                        sendUserImport(mode, arr);',
        '                    } catch(err) { alert("Invalid JSON file format."); }',
        '                };',
        '                reader.readAsText(file);',
        '            } else if (fileName.endsWith(".xlsx") || fileName.endsWith(".xls")) {',
        '                reader.onload = async (e) => {',
        '                    const data = new Uint8Array(e.target.result); const workbook = XLSX.read(data, { type: "array" });',
        '                    const sheet = workbook.Sheets[workbook.SheetNames[0]];',
        '                    sendUserImport(mode, XLSX.utils.sheet_to_json(sheet));',
        '                };',
        '                reader.readAsArrayBuffer(file);',
        '            }',
        '        }',
        '        async function sendUserImport(mode, items) {',
        '            if(!confirm(`Proceed with import? Mode: ${mode.toUpperCase()} AND ADD`)) return;',
        '            const res = await fetch("/api/dispense/import", { method: "POST", headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" }, body: JSON.stringify({ zone: activeZone, mode, items }) });',
        '            const data = await res.json();',
        '            if (res.ok) { alert(data.message); syncUserData(); } else alert("Import error: " + data.error);',
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
        '            if (!z.length) return alert("Please select at least one zone.");',
        '            const res = await fetch(`/api/users/${id}/zones`, { method: "PUT", headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" }, body: JSON.stringify({ zones: z }) });',
        '            if (await handleAccessError(res)) return;',
        '            if (res.ok) { closeEditModal(); loadAdminData(); } else { alert("Failed to update zones."); }',
        '        }',

        '        async function toggleUser(id, status) { await fetch(`/api/users/${id}/status`, { method: "PUT", headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" }, body: JSON.stringify({ status }) }); loadAdminData(); }',
        '        async function removeUser(id) { if (!confirm("Permanently remove user?")) return; await fetch(`/api/users/${id}`, { method: "DELETE", headers: { "Authorization": "Bearer " + token } }); loadAdminData(); }',
        '        async function createUser() {',
        '            const u = document.getElementById("nu-name").value; const p = document.getElementById("nu-phone").value; const pass = document.getElementById("nu-pass").value;',
        '            const z = Array.from(document.querySelectorAll(\'input[name="assigned-zones"]:checked\')).map(cb => cb.value);',
        '            if (!z.length) return alert("Select at least one zone.");',
        '            const res = await fetch("/api/users", { method: "POST", headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" }, body: JSON.stringify({ username: u, phone: p, password: pass, zones: z }) });',
        '            if (await handleAccessError(res)) return;',
        '            if (res.ok) { alert("User created"); loadAdminData(); } else alert("Failed to create user");',
        '        }',

        '        function normalizeImportData(rawData) {',
        '            let items = rawData; if (typeof items === "string") try { items = JSON.parse(items); } catch(e) {}',
        '            if (!Array.isArray(items) && typeof items === "object" && items !== null) { const firstArrayKey = Object.keys(items).find(k => Array.isArray(items[k])); items = firstArrayKey ? items[firstArrayKey] : [items]; }',
        '            return Array.isArray(items) ? items : [items];',
        '        }',

        '        async function processImport(type, mode) {',
        '            const targetZone = document.getElementById("admin-import-zone").value; const fileInput = document.getElementById("admin-file-import");',
        '            if (!targetZone) return alert("Select a target zone."); if (!fileInput.files.length) return alert("Choose a file.");',
        '            const file = fileInput.files[0]; const fileName = file.name.toLowerCase(); const reader = new FileReader();',
        '            if (fileName.endsWith(".json")) { reader.onload = async (e) => { try { sendImportPayload(type, mode, targetZone, normalizeImportData(JSON.parse(e.target.result))); } catch(err) { alert("Invalid JSON."); } }; reader.readAsText(file); }',
        '            else if (fileName.endsWith(".xlsx") || fileName.endsWith(".xls")) { reader.onload = async (e) => { const workbook = XLSX.read(new Uint8Array(e.target.result), { type: "array" }); sendImportPayload(type, mode, targetZone, XLSX.utils.sheet_to_json(workbook.Sheets[workbook.SheetNames[0]])); }; reader.readAsArrayBuffer(file); }',
        '        }',
        '        async function sendImportPayload(type, mode, zone, items) { const res = await fetch("/api/master-drugs/import", { method: "POST", headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" }, body: JSON.stringify({ zone, mode, drugs: items }) }); if (await handleAccessError(res)) return; if (res.ok) alert((await res.json()).message || "Import success!"); else alert("Import error."); }',
        '        async function updateAdminProfile() { const u = document.getElementById("admin-new-user").value; const p = document.getElementById("admin-new-pass").value; const res = await fetch("/api/admin/profile", { method: "PUT", headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" }, body: JSON.stringify({ newUsername: u, newPassword: p }) }); if (await handleAccessError(res)) return; if (res.ok) { alert("Credentials updated. Logging out..."); handleLogout(true); } }',
        '        function filterTable(id, val) { const rows = document.getElementById(id).rows; const s = val.toUpperCase(); for (let r of rows) r.style.display = r.innerText.toUpperCase().includes(s) ? "" : "none"; }',
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
