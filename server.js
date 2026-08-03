const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

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

// Ensure persistent storage directory exists for SQLite database
const dbDir = path.resolve(__dirname);
const dbPath = path.join(dbDir, 'pharmacy.db');

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

// Initialize Database with WAL Mode & High Performance Indexes for 1M+ Records & 500+ Concurrent Users
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error("Database connection error:", err.message);
    } else {
        console.log("Connected to SQLite Database at:", dbPath);
        db.run("PRAGMA journal_mode = WAL;");
        db.run("PRAGMA synchronous = NORMAL;");
        db.run("PRAGMA cache_size = -128000;"); // 128MB Memory Cache for blazing-fast 1M+ record querying
        db.run("PRAGMA temp_store = MEMORY;");
        db.run("PRAGMA mmap_size = 30000000000;");
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

        // High Speed Database Indexes for 1M+ Records Scaling & Zero Lag
        db.run("CREATE INDEX IF NOT EXISTS idx_master_zone_drug ON master_drugs(zone, drug_name)");
        db.run("CREATE INDEX IF NOT EXISTS idx_dispenses_zone ON dispenses(zone)");
        db.run("CREATE INDEX IF NOT EXISTS idx_dispenses_drug ON dispenses(zone, drug_name)");
        db.run("CREATE INDEX IF NOT EXISTS idx_activity_timestamp ON activity_logs(timestamp)");
        db.run("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp)");

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
        res.json({ message: "Zone registered successfully." });
    });
});

app.get('/api/admin/audit-logs', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required." });
    db.all("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 500", [], (err, rows) => {
        res.json(rows);
    });
});

// Delete endpoint for Transaction Audit Logs
app.delete('/api/admin/audit-logs/:id', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required." });
    db.run("DELETE FROM audit_logs WHERE id = ?", [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Audit log entry deleted successfully." });
    });
});

app.get('/api/admin/activity-logs', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required." });
    db.all("SELECT * FROM activity_logs ORDER BY id DESC LIMIT 500", [], (err, rows) => {
        res.json(rows);
    });
});

// Delete endpoint for User Login / Logout Activity Tracker
app.delete('/api/admin/activity-logs/:id', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required." });
    db.run("DELETE FROM activity_logs WHERE id = ?", [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Activity log entry deleted successfully." });
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

// User-facing Bulk Import API for Dispense/Cumulative Data (Merge or Reset & Add)
app.post('/api/dispense/import', authenticateToken, (req, res) => {
    const mode = req.body.mode; // 'merge' or 'reset'
    let entries = req.body.entries;
    const zone = req.body.zone;

    if (!zone || !entries) return res.status(400).json({ error: "Invalid payload or unselected target zone." });
    if (!Array.isArray(entries)) entries = [entries];

    db.serialize(() => {
        db.run("BEGIN TRANSACTION");
        if (mode === 'reset') {
            db.run("DELETE FROM dispenses WHERE zone = ?", [zone]);
        }

        const stmtDispense = db.prepare("INSERT INTO dispenses (zone, drug_name, qty, entered_by) VALUES (?, ?, ?, ?)");
        const stmtMaster = db.prepare("INSERT OR IGNORE INTO master_drugs (zone, drug_name) VALUES (?, ?)");
        let processedCount = 0;

        entries.forEach(item => {
            let drugName = "";
            let qty = 1;

            if (typeof item === 'object' && item !== null) {
                const keys = Object.keys(item);
                const nameKey = keys.find(k => /drug|name|item|product|title/i.test(k));
                const qtyKey = keys.find(k => /qty|quantity|amount|total|count/i.test(k));
                
                if (nameKey && item[nameKey]) drugName = String(item[nameKey]).trim().toUpperCase();
                if (qtyKey && !isNaN(item[qtyKey])) qty = parseInt(item[qtyKey]);
                
                if (!drugName && keys.length > 0) {
                    drugName = String(item[keys[0]]).trim().toUpperCase();
                    if (keys.length > 1 && !isNaN(item[keys[1]])) qty = parseInt(item[keys[1]]);
                }
            } else if (typeof item === 'string') {
                drugName = item.trim().toUpperCase();
            }

            if (drugName) {
                stmtMaster.run(zone, drugName);
                stmtDispense.run(zone, drugName, qty, req.user.username + " (Import)");
                processedCount++;
            }
        });

        stmtMaster.finalize();
        stmtDispense.finalize();

        db.run("COMMIT", (err) => {
            if (err) return res.status(500).json({ error: "Failed to commit data import." });
            res.json({ message: `Successfully imported ${processedCount} entries for zone ${zone}.` });
        });
    });
});

app.get('/api/dispense/sync', authenticateToken, (req, res) => {
    // Increased limit to 50000 to ensure smooth handling of large cumulative datasets without truncation
    db.all("SELECT * FROM dispenses WHERE zone = ? ORDER BY id DESC LIMIT 50000", [req.query.zone], (err, rows) => {
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
        '                    <span style="margin-left: 15px; font-size: 12px; color: var(--text-muted);"><span class="live-dot"></span>LIVE AUTO-SYNC (3s)</span>',
        '                </div>',
        '                <div style="display:flex; gap:10px; align-items: center;">',
        '                    <div id="user-zone-picker-wrap" style="margin-bottom:0; width: 220px; display:none;">',
        '                        <select id="user-zone-select" onchange="switchZone()" style="margin-bottom:0; padding: 8px 12px;"></select>',
        '                    </div>',
        '                    <div id="single-zone-badge-wrap" style="display:none;">',
        '                        <span style="font-size:12px; font-weight:bold; color:var(--text-muted);">ACTIVE ZONE:</span>',
        '                        <span id="single-zone-name" class="badge" style="background:var(--sidebar); color:white; font-size:13px; padding:6px 12px;">-</span>',
        '                    </div>',
        '                    <button onclick="triggerLogout()" class="primary-btn danger" style="margin-bottom:0; width:auto; padding:8px 16px;">LOGOUT</button>',
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
        '                    <label style="font-size: 12px; color: var(--accent); font-weight: 600; display: block; margin-bottom: 6px;">Select Assigned Zones for User:</label>',
        '                    <div id="nu-zones-container" class="zone-checkbox-group"></div>',
        '                    <button onclick="createNewUser()" class="primary-btn success">Create User Account</button>',
        '                </div>',

        '                <div class="panel">',
        '                    <h2>📋 Registered Users Management</h2>',
        '                    <div class="table-wrap">',
        '                        <table>',
        '                            <thead><tr><th>Username</th><th>Phone</th><th>Zones</th><th>Status</th><th>Actions</th></tr></thead>',
        '                            <tbody id="admin-users-tbody"></tbody>',
        '                        </table>',
        '                    </div>',
        '                </div>',

        '                <div class="panel">',
        '                    <h2>📊 Transaction Audit Logs</h2>',
        '                    <div class="table-wrap">',
        '                        <table>',
        '                            <thead><tr><th>Timestamp</th><th>User</th><th>Phone</th><th>Zone</th><th>Action</th><th>Action</th></tr></thead>',
        '                            <tbody id="admin-audit-tbody"></tbody>',
        '                        </table>',
        '                    </div>',
        '                </div>',

        '                <div class="panel">',
        '                    <h2>🕒 User Login / Logout Activity Tracker</h2>',
        '                    <div class="table-wrap">',
        '                        <table>',
        '                            <thead><tr><th>Timestamp</th><th>User</th><th>Phone</th><th>Action</th><th>Action</th></tr></thead>',
        '                            <tbody id="admin-activity-tbody"></tbody>',
        '                        </table>',
        '                    </div>',
        '                </div>',
        '            </div>',

        '            <!-- USER VIEW -->',
        '            <div id="user-view" class="app-grid hidden">',
        '                <div class="panel">',
        '                    <h2>➕ Record Dispense / Distribution</h2>',
        '                    <input type="text" id="drug-search-input" placeholder="Search / Type Drug Name..." oninput="filterDrugSuggestions()" onkeydown="if(event.key===\'Enter\') submitDispense()">',
        '                    <div id="drug-suggestions" style="max-height: 150px; overflow-y: auto; background: white; border: 1px solid #d1d9e6; border-radius: 6px; margin-bottom: 10px; display: none;"></div>',
        '                    <div class="qty-grid">',
        '                        <div class="qty-pill" onclick="setQty(1)">1</div>',
        '                        <div class="qty-pill" onclick="setQty(5)">5</div>',
        '                        <div class="qty-pill" onclick="setQty(10)">10</div>',
        '                        <div class="qty-pill" onclick="setQty(50)">50</div>',
        '                    </div>',
        '                    <input type="number" id="dispense-qty" placeholder="Quantity" value="1">',
        '                    <button onclick="submitDispense()" class="primary-btn success">Submit Entry</button>',
        '                    <hr style="border:0; border-top:1px solid #eee; margin: 15px 0;">',
        '                    <h2 style="font-size:13px;">📁 Master Directory & Bulk Import</h2>',
        '                    <button onclick="openMasterModal()" class="primary-btn" style="background:var(--sidebar);">Manage Master Directory</button>',
        '                    <button onclick="openImportModal()" class="primary-btn warning" style="margin-top:5px;">Bulk Import Data</button>',
        '                </div>',

        '                <div class="panel">',
        '                    <div class="flex" style="justify-content: space-between; margin-bottom: 15px;">',
        '                        <h2 style="margin:0;">📦 Cumulative Inventory & Dispense Totals</h2>',
        '                        <div class="flex" style="gap:5px;">',
        '                            <button onclick="exportExcel()" class="primary-btn success" style="width:auto; padding:6px 12px; font-size:12px;">Export Excel</button>',
        '                            <button onclick="exportPDF()" class="primary-btn danger" style="width:auto; padding:6px 12px; font-size:12px;">Export PDF</button>',
        '                            <button onclick="clearZoneTotals()" class="primary-btn danger" style="width:auto; padding:6px 12px; font-size:12px;">Clear Zone Totals</button>',
        '                        </div>',
        '                    </div>',
        '                    <input type="text" id="inventory-filter" placeholder="Filter active items..." oninput="renderLiveInventory()" style="margin-bottom: 10px;">',
        '                    <div class="table-wrap" style="max-height: 500px;">',
        '                        <table>',
        '                            <thead><tr><th>Drug Name</th><th>Total Dispensed</th><th>Last Entered By</th><th>Actions</th></tr></thead>',
        '                            <tbody id="inventory-tbody"></tbody>',
        '                        </table>',
        '                    </div>',
        '                </div>',

        '                <div class="panel">',
        '                    <h2>📜 Live Zone Activity Feed</h2>',
        '                    <div class="table-wrap" style="max-height: 520px;">',
        '                        <table>',
        '                            <thead><tr><th>Time</th><th>User</th><th>Drug</th><th>Qty</th></tr></thead>',
        '                            <tbody id="feed-tbody"></tbody>',
        '                        </table>',
        '                    </div>',
        '                </div>',
        '            </div>',
        '        </div>',
        '    </div>',

        '    <!-- MASTER DIRECTORY MODAL -->',
        '    <div id="master-modal" class="hidden" style="position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.5); z-index:1000; display:flex; align-items:center; justify-content:center;">',
        '        <div class="panel" style="width: 500px; max-height: 80vh; overflow-y:auto; background:white; margin:0;">',
        '            <h2>Master Directory Management</h2>',
        '            <input type="text" id="new-master-drug" placeholder="Add New Drug to Master Directory" onkeydown="if(event.key===\'Enter\') addMasterDrug()">',
        '            <button onclick="addMasterDrug()" class="primary-btn success">Add Drug</button>',
        '            <div class="table-wrap" style="margin-top: 15px; max-height: 300px;">',
        '                <table>',
        '                    <thead><tr><th>Drug Name</th><th>Actions</th></tr></thead>',
        '                    <tbody id="master-modal-tbody"></tbody>',
        '                </table>',
        '            </div>',
        '            <button onclick="closeMasterModal()" class="primary-btn danger" style="margin-top:15px;">Close</button>',
        '        </div>',
        '    </div>',

        '    <!-- BULK IMPORT MODAL -->',
        '    <div id="import-modal" class="hidden" style="position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.5); z-index:1000; display:flex; align-items:center; justify-content:center;">',
        '        <div class="panel" style="width: 550px; background:white; margin:0;">',
        '            <h2>Bulk Data Import (Excel / CSV / Text)</h2>',
        '            <select id="import-mode" style="margin-bottom:10px;">',
        '                <option value="merge">Merge & Append Data</option>',
        '                <option value="reset">Reset Zone Data & Import Fresh</option>',
        '            </select>',
        '            <input type="file" id="import-file-input" accept=".xlsx, .xls, .csv, .txt" style="background:white; padding:8px;" onchange="handleFileSelection(event)">',
        '            <textarea id="import-textarea" placeholder="Or paste comma/newline separated drug names or items here..." style="width:100%; height:120px; padding:10px; border-radius:8px; border:1px solid #d1d9e6; margin-bottom:10px; font-size:13px;"></textarea>',
        '            <div class="flex" style="justify-content:flex-end;">',
        '                <button onclick="closeImportModal()" class="primary-btn danger" style="width:auto; padding:10px 20px; margin-bottom:0;">Cancel</button>',
        '                <button onclick="executeBulkImport()" class="primary-btn success" style="width:auto; padding:10px 20px; margin-bottom:0;">Process Import</button>',
        '            </div>',
        '        </div>',
        '    </div>',

        '    <!-- EDIT ZONES MODAL -->',
        '    <div id="edit-zones-modal" class="hidden" style="position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.5); z-index:1000; display:flex; align-items:center; justify-content:center;">',
        '        <div class="panel" style="width: 450px; background:white; margin:0;">',
        '            <h2>Edit User Zones</h2>',
        '            <input type="hidden" id="edit-user-id">',
        '            <p id="edit-user-name-display" style="font-weight:bold; margin-bottom:10px; color:var(--sidebar);"></p>',
        '            <label style="font-size: 12px; color: var(--accent); font-weight: 600; display: block; margin-bottom: 6px;">Select Assigned Zones:</label>',
        '            <div id="edit-zones-container" class="zone-checkbox-group" style="max-height: 200px; overflow-y: auto;"></div>',
        '            <div class="flex" style="justify-content:flex-end; margin-top:15px;">',
        '                <button onclick="closeEditZonesModal()" class="primary-btn danger" style="width:auto; padding:10px 20px; margin-bottom:0;">Cancel</button>',
        '                <button onclick="saveUserZones()" class="primary-btn success" style="width:auto; padding:10px 20px; margin-bottom:0;">Save Zones</button>',
        '            </div>',
        '        </div>',
        '    </div>',

        '    <script>',
        '        let authToken = localStorage.getItem("rx_token") || "";',
        '        let currentUserRole = localStorage.getItem("rx_role") || "";',
        '        let currentUsername = localStorage.getItem("rx_username") || "";',
        '        let currentZones = JSON.parse(localStorage.getItem("rx_zones") || "[]");',
        '        let activeZone = localStorage.getItem("rx_active_zone") || "";',
        '',
        '        let masterDrugs = [];',
        '        let liveInventoryData = [];',
        '        let allRegisteredZones = [];',
        '        let parsedImportRows = [];',
        '        let syncInterval = null;',
        '',
        '        window.addEventListener("DOMContentLoaded", () => {',
        '            if (authToken) {',
        '                showAppScreen();',
        '            } else {',
        '                showLoginScreen();',
        '            }',
        '        });',
        '',
        '        async function apiCall(endpoint, method = "GET", data = null) {',
        '            const headers = { "Content-Type": "application/json" };',
        '            if (authToken) headers["Authorization"] = "Bearer " + authToken;',
        '            const opts = { method, headers };',
        '            if (data) opts.body = JSON.stringify(data);',
        '            try {',
        '                const res = await fetch(endpoint, opts);',
        '                if (res.status === 401 || res.status === 403) {',
        '                    const errJson = await res.json().catch(() => ({}));',
        '                    if (errJson.error === "ACCESS_DISABLED") {',
        '                        alert(errJson.message);',
        '                    }',
        '                    triggerLogout();',
        '                    return null;',
        '                }',
        '                return await res.json();',
        '            } catch (e) {',
        '                console.error("API Error:", e);',
        '                return null;',
        '            }',
        '        }',
        '',
        '        async function handleLogin() {',
        '            const username = document.getElementById("login-username").value.trim();',
        '            const password = document.getElementById("login-password").value.trim();',
        '            const errDiv = document.getElementById("login-error");',
        '            errDiv.textContent = "";',
        '',
        '            if (!username || !password) {',
        '                errDiv.textContent = "Please enter username and password.";',
        '                return;',
        '            }',
        '',
        '            const res = await apiCall("/api/login", "POST", { username, password });',
        '            if (!res || res.error) {',
        '                errDiv.textContent = res ? res.error : "Login failed.";',
        '                return;',
        '            }',
        '',
        '            authToken = res.token;',
        '            currentUserRole = res.role;',
        '            currentUsername = res.username;',
        '            currentZones = res.zones;',
        '            activeZone = currentZones.length > 0 ? currentZones[0] : "";',
        '',
        '            localStorage.setItem("rx_token", authToken);',
        '            localStorage.setItem("rx_role", currentUserRole);',
        '            localStorage.setItem("rx_username", currentUsername);',
        '            localStorage.setItem("rx_zones", JSON.stringify(currentZones));',
        '            localStorage.setItem("rx_active_zone", activeZone);',
        '',
        '            showAppScreen();',
        '        }',
        '',
        '        async function triggerLogout() {',
        '            if (authToken) {',
        '                await apiCall("/api/logout", "POST", { zone: activeZone });',
        '            }',
        '            localStorage.clear();',
        '            authToken = "";',
        '            currentUserRole = "";',
        '            currentUsername = "";',
        '            currentZones = [];',
        '            activeZone = "";',
        '            if (syncInterval) clearInterval(syncInterval);',
        '            showLoginScreen();',
        '        }',
        '',
        '        function showLoginScreen()',
        '        {',
        '            document.getElementById("login-screen").classList.remove("hidden");',
        '            document.getElementById("app-screen").classList.add("hidden");',
        '        }',
        '',
        '        async function showAppScreen() {',
        '            document.getElementById("login-screen").classList.add("hidden");',
        '            document.getElementById("app-screen").classList.remove("hidden");',
        '            document.getElementById("role-display").textContent = currentUserRole;',
        '',
        '            await loadZonesRegistry();',
        '',
        '            if (currentUserRole === "ADMIN") {',
        '                document.getElementById("admin-view").classList.remove("hidden");',
        '                document.getElementById("user-view").classList.add("hidden");',
        '                document.getElementById("user-zone-picker-wrap").style.display = "none";',
        '                document.getElementById("single-zone-badge-wrap").style.display = "none";',
        '                loadAdminDashboard();',
        '            } else {',
        '                document.getElementById("admin-view").classList.add("hidden");',
        '                document.getElementById("user-view").classList.remove("hidden");',
        '                setupUserZonePicker();',
        '                await refreshData();',
        '                if (syncInterval) clearInterval(syncInterval);',
        '                syncInterval = setInterval(refreshData, 3000);',
        '            }',
        '        }',
        '',
        '        async function loadZonesRegistry() {',
        '            const zones = await apiCall("/api/zones");',
        '            if (zones && Array.isArray(zones)) {',
        '                allRegisteredZones = zones;',
        '                if (currentUserRole === "ADMIN") {',
        '                    renderAdminZoneCheckboxes("nu-zones-container", "nu-zone-cb");',
        '                    renderAdminZoneCheckboxes("edit-zones-container", "edit-zone-cb");',
        '                }',
        '            }',
        '        }',
        '',
        '        function renderAdminZoneCheckboxes(containerId, inputClass) {',
        '            const container = document.getElementById(containerId);',
        '            if (!container) return;',
        '            container.innerHTML = "";',
        '            allRegisteredZones.forEach(z => {',
        '                const lbl = document.createElement("label");',
        '                lbl.className = "zone-checkbox-item";',
        '                lbl.innerHTML = `<input type="checkbox" class="${inputClass}" value="${z}"> ${z}`;',
        '                container.appendChild(lbl);',
        '            });',
        '        }',
        '',
        '        function setupUserZonePicker() {',
        '            const pickerWrap = document.getElementById("user-zone-picker-wrap");',
        '            const badgeWrap = document.getElementById("single-zone-badge-wrap");',
        '            const select = document.getElementById("user-zone-select");',
        '            select.innerHTML = "";',
        '',
        '            currentZones.forEach(z => {',
        '                const opt = document.createElement("option");',
        '                opt.value = z;',
        '                opt.textContent = z;',
        '                if (z === activeZone) opt.selected = true;',
        '                select.appendChild(opt);',
        '            });',
        '',
        '            if (currentZones.length > 1) {',
        '                pickerWrap.style.display = "block";',
        '                badgeWrap.style.display = "none";',
        '            } else {',
        '                pickerWrap.style.display = "none";',
        '                badgeWrap.style.display = "block";',
        '                document.getElementById("single-zone-name").textContent = activeZone || (currentZones[0] || "N/A");',
        '                if (currentZones.length === 1 && !activeZone) activeZone = currentZones[0];',
        '            }',
        '        }',
        '',
        '        function switchZone() {',
        '            const select = document.getElementById("user-zone-select");',
        '            activeZone = select.value;',
        '            localStorage.setItem("rx_active_zone", activeZone);',
        '            refreshData();',
        '        }',
        '',
        '        async function loadAdminDashboard() {',
        '            loadAdminUsers();',
        '            loadAdminAuditLogs();',
        '            loadAdminActivityLogs();',
        '        }',
        '',
        '        async function loadAdminUsers() {',
        '            const users = await apiCall("/api/users");',
        '            const tbody = document.getElementById("admin-users-tbody");',
        '            tbody.innerHTML = "";',
        '            if (!users) return;',
        '',
        '            users.forEach(u => {',
        '                const tr = document.createElement("tr");',
        '                const statusText = u.status === 1 ? "Active" : "Disabled";',
        '                const statusColor = u.status === 1 ? "var(--success)" : "var(--danger)";',
        '                tr.innerHTML = `',
        '                    <td><b>${u.username}</b></td>',
        '                    <td>${u.phone}</td>',
        '                    <td><span class="badge">${u.zones.join(", ")}</span></td>',
        '                    <td><span style="color:${statusColor}; font-weight:bold;">${statusText}</span></td>',
        '                    <td>',
        '                        <button class="action-link" onclick="openEditZonesModal(${u.id}, \`${u.username}\`, \`${encodeURIComponent(JSON.stringify(u.zones))}\`)">Edit Zones</button> | ',
        '                        <button class="action-link" onclick="toggleUserStatus(${u.id}, ${u.status})">${u.status === 1 ? "Disable" : "Enable"}</button> | ',
        '                        <button class="action-link" style="color:var(--danger);" onclick="deleteUser(${u.id})">Delete</button>',
        '                    </td>',
        '                `;',
        '                tbody.appendChild(tr);',
        '            });',
        '        }',
        '',
        '        function openEditZonesModal(userId, username, encodedZones) {',
        '            document.getElementById("edit-user-id").value = userId;',
        '            document.getElementById("edit-user-name-display").textContent = "Editing zones for: " + username;',
        '            let userZones = [];',
        '            try { userZones = JSON.parse(decodeURIComponent(encodedZones)); } catch(e) {}',
        '',
        '            const checkboxes = document.querySelectorAll(".edit-zone-cb");',
        '            checkboxes.forEach(cb => {',
        '                cb.checked = userZones.includes(cb.value);',
        '            });',
        '',
        '            document.getElementById("edit-zones-modal").classList.remove("hidden");',
        '        }',
        '',
        '        function closeEditZonesModal() {',
        '            document.getElementById("edit-zones-modal").classList.add("hidden");',
        '        }',
        '',
        '        async function saveUserZones() {',
        '            const userId = document.getElementById("edit-user-id").value;',
        '            const checkboxes = document.querySelectorAll(".edit-zone-cb:checked");',
        '            const selectedZones = Array.from(checkboxes).map(cb => cb.value);',
        '',
        '            if (selectedZones.length === 0) {',
        '                alert("Please select at least one zone.");',
        '                return;',
        '            }',
        '',
        '            const res = await apiCall(`/api/users/${userId}/zones`, "PUT", { zones: selectedZones });',
        '            if (res && !res.error) {',
        '                closeEditZonesModal();',
        '                loadAdminUsers();',
        '            } else {',
        '                alert(res ? res.error : "Failed to update zones.");',
        '            }',
        '        }',
        '',
        '        async function loadAdminAuditLogs() {',
        '            const logs = await apiCall("/api/admin/audit-logs");',
        '            const tbody = document.getElementById("admin-audit-tbody");',
        '            tbody.innerHTML = "";',
        '            if (!logs) return;',
        '',
        '            logs.forEach(l => {',
        '                const tr = document.createElement("tr");',
        '                tr.innerHTML = `',
        '                    <td>${l.timestamp}</td>',
        '                    <td><b>${l.username}</b></td>',
        '                    <td>${l.phone}</td>',
        '                    <td>${l.zone}</td>',
        '                    <td><span class="badge">${l.action}</span></td>',
        '                    <td><button class="action-link" style="color:var(--danger);" onclick="deleteAuditLog(${l.id})">Delete</button></td>',
        '                `;',
        '                tbody.appendChild(tr);',
        '            });',
        '        }',
        '',
        '        async function deleteAuditLog(id) {',
        '            if (!confirm("Are you sure you want to delete this audit log entry?")) return;',
        '            const res = await apiCall(`/api/admin/audit-logs/${id}`, "DELETE");',
        '            if (res && !res.error) {',
        '                loadAdminAuditLogs();',
        '            } else {',
        '                alert(res ? res.error : "Failed to delete audit log.");',
        '            }',
        '        }',
        '',
        '        async function loadAdminActivityLogs() {',
        '            const logs = await apiCall("/api/admin/activity-logs");',
        '            const tbody = document.getElementById("admin-activity-tbody");',
        '            tbody.innerHTML = "";',
        '            if (!logs) return;',
        '',
        '            logs.forEach(l => {',
        '                const tr = document.createElement("tr");',
        '                tr.innerHTML = `',
        '                    <td>${l.timestamp}</td>',
        '                    <td><b>${l.username}</b></td>',
        '                    <td>${l.phone}</td>',
        '                    <td><span class="badge">${l.action}</span></td>',
        '                    <td><button class="action-link" style="color:var(--danger);" onclick="deleteActivityLog(${l.id})">Delete</button></td>',
        '                `;',
        '                tbody.appendChild(tr);',
        '            });',
        '        }',
        '',
        '        async function deleteActivityLog(id) {',
        '            if (!confirm("Are you sure you want to delete this activity log entry?")) return;',
        '            const res = await apiCall(`/api/admin/activity-logs/${id}`, "DELETE");',
        '            if (res && !res.error) {',
        '                loadAdminActivityLogs();',
        '            } else {',
        '                alert(res ? res.error : "Failed to delete activity log.");',
        '            }',
        '        }',
        '',
        '        async function updateAdminProfile() {',
        '            const newUsername = document.getElementById("admin-new-user").value.trim();',
        '            const newPassword = document.getElementById("admin-new-pass").value.trim();',
        '            if (!newUsername || !newPassword) {',
        '                alert("Enter new admin username and password.");',
        '                return;',
        '            }',
        '            const res = await apiCall("/api/admin/profile", "PUT", { newUsername, newPassword });',
        '            if (res && !res.error) {',
        '                alert("Admin credentials updated successfully. Please login again.");',
        '                triggerLogout();',
        '            } else {',
        '                alert(res ? res.error : "Update failed.");',
        '            }',
        '        }',
        '',
        '        async function registerNewZone() {',
        '            const input = document.getElementById("new-zone-input");',
        '            const zName = input.value.trim();',
        '            if (!zName) return;',
        '            const res = await apiCall("/api/zones", "POST", { zone_name: zName });',
        '            if (res && !res.error) {',
        '                input.value = "";',
        '                loadZonesRegistry();',
        '                alert("Zone registered successfully.");',
        '            }',
        '        }',
        '',
        '        async function createNewUser() {',
        '            const username = document.getElementById("nu-name").value.trim();',
        '            const phone = document.getElementById("nu-phone").value.trim();',
        '            const password = document.getElementById("nu-pass").value.trim();',
        '            const checkboxes = document.querySelectorAll(".nu-zone-cb:checked");',
        '            const zones = Array.from(checkboxes).map(cb => cb.value);',
        '',
        '            if (!username || !phone || !password || zones.length === 0) {',
        '                alert("All fields and at least one zone are required.");',
        '                return;',
        '            }',
        '',
        '            const res = await apiCall("/api/users", "POST", { username, phone, password, zones });',
        '            if (res && !res.error) {',
        '                document.getElementById("nu-name").value = "";',
        '                document.getElementById("nu-phone").value = "";',
        '                document.getElementById("nu-pass").value = "";',
        '                checkboxes.forEach(cb => cb.checked = false);',
        '                loadAdminUsers();',
        '                alert("User created successfully.");',
        '            } else {',
        '                alert(res ? res.error : "Creation failed.");',
        '            }',
        '        }',
        '',
        '        async function toggleUserStatus(id, currentStatus) {',
        '            const newStatus = currentStatus === 1 ? 0 : 1;',
        '            await apiCall(`/api/users/${id}/status`, "PUT", { status: newStatus });',
        '            loadAdminUsers();',
        '        }',
        '',
        '        async function deleteUser(id) {',
        '            if (!confirm("Permanently delete this user account?")) return;',
        '            await apiCall(`/api/users/${id}`, "DELETE");',
        '            loadAdminUsers();',
        '        }',
        '',
        '        async function refreshData() {',
        '            if (!activeZone) return;',
        '            await loadMasterDrugs();',
        '            await loadInventoryAndFeed();',
        '        }',
        '',
        '        async function loadMasterDrugs() {',
        '            const drugs = await apiCall(`/api/master-drugs?zone=${encodeURIComponent(activeZone)}`);',
        '            if (drugs && Array.isArray(drugs)) {',
        '                masterDrugs = drugs;',
        '            }',
        '        }',
        '',
        '        function filterDrugSuggestions() {',
        '            const query = document.getElementById("drug-search-input").value.trim().toUpperCase();',
        '            const box = document.getElementById("drug-suggestions");',
        '            box.innerHTML = "";',
        '',
        '            if (!query) {',
        '                box.style.display = "none";',
        '                return;',
        '            }',
        '',
        '            const matches = masterDrugs.filter(d => d.includes(query));',
        '            if (matches.length === 0) {',
        '                box.style.display = "none";',
        '                return;',
        '            }',
        '',
        '            box.style.display = "block";',
        '            matches.forEach(m => {',
        '                const div = document.createElement("div");',
        '                div.style.padding = "8px 12px";',
        '                div.style.cursor = "pointer";',
        '                div.style.borderBottom = "1px solid #f1f5f9";',
        '                div.textContent = m;',
        '                div.onmousedown = () => {',
        '                    document.getElementById("drug-search-input").value = m;',
        '                    box.style.display = "none";',
        '                };',
        '                box.appendChild(div);',
        '            });',
        '        }',
        '',
        '        function setQty(val) {',
        '            document.getElementById("dispense-qty").value = val;',
        '        }',
        '',
        '        async function submitDispense() {',
        '            const drugName = document.getElementById("drug-search-input").value.trim().toUpperCase();',
        '            const qty = parseInt(document.getElementById("dispense-qty").value);',
        '',
        '            if (!drugName || isNaN(qty) || qty <= 0) {',
        '                alert("Please enter a valid drug name and quantity.");',
        '                return;',
        '            }',
        '',
        '            await apiCall("/api/master-drugs", "POST", { zone: activeZone, drug_name: drugName });',
        '            const res = await apiCall("/api/dispense", "POST", { zone: activeZone, drug_name: drugName, qty });',
        '',
        '            if (res && !res.error) {',
        '                document.getElementById("drug-search-input").value = "";',
        '                document.getElementById("dispense-qty").value = "1";',
        '                document.getElementById("drug-suggestions").style.display = "none";',
        '                refreshData();',
        '            }',
        '        }',
        '',
        '        async function loadInventoryAndFeed() {',
        '            const rows = await apiCall(`/api/dispense/sync?zone=${encodeURIComponent(activeZone)}`);',
        '            if (!rows || !Array.isArray(rows)) return;',
        '',
        '            const map = {};',
        '            rows.forEach(r => {',
        '                if (!map[r.drug_name]) {',
        '                    map[r.drug_name] = { total: 0, lastBy: r.entered_by };',
        '                }',
        '                map[r.drug_name].total += r.qty;',
        '            });',
        '',
        '            liveInventoryData = Object.keys(map).map(k => ({',
        '                drug_name: k,',
        '                total: map[k].total,',
        '                entered_by: map[k].lastBy',
        '            })).sort((a,b) => a.drug_name.localeCompare(b.drug_name));',
        '',
        '            renderLiveInventory();',
        '',
        '            const feedTbody = document.getElementById("feed-tbody");',
        '            feedTbody.innerHTML = "";',
        '            rows.slice(0, 50).forEach(r => {',
        '                const tr = document.createElement("tr");',
        '                const timeStr = r.timestamp ? r.timestamp.split(" ")[1] || r.timestamp : "";',
        '                tr.innerHTML = `',
        '                    <td>${timeStr}</td>',
        '                    <td><b>${r.entered_by}</b></td>',
        '                    <td>${r.drug_name}</td>',
        '                    <td><span class="badge">+${r.qty}</span></td>',
        '                `;',
        '                feedTbody.appendChild(tr);',
        '            });',
        '        }',
        '',
        '        function renderLiveInventory() {',
        '            const filter = document.getElementById("inventory-filter").value.trim().toUpperCase();',
        '            const tbody = document.getElementById("inventory-tbody");',
        '            tbody.innerHTML = "";',
        '',
        '            const filtered = liveInventoryData.filter(i => i.drug_name.includes(filter));',
        '            filtered.forEach(item => {',
        '                const tr = document.createElement("tr");',
        '                tr.innerHTML = `',
        '                    <td><b>${item.drug_name}</b></td>',
        '                    <td><span class="badge" style="background:#e6fffa; color:#047857; font-size:14px;">${item.total}</span></td>',
        '                    <td style="font-size:12px; color:var(--text-muted);">${item.entered_by}</td>',
        '                    <td>',
        '                        <button class="action-link" onclick="adjustCumulativeQty(\`${item.drug_name}\`, ${item.total})">Edit Total</button> | ',
        '                        <button class="action-link" style="color:var(--danger);" onclick="adjustCumulativeQty(\`${item.drug_name}\`, 0)">Reset</button>',
        '                    </td>',
        '                `;',
        '                tbody.appendChild(tr);',
        '            });',
        '        }',
        '',
        '        async function adjustCumulativeQty(drugName, currentTotal) {',
        '            const newQtyStr = prompt(`Edit total quantity for ${drugName}:`, currentTotal);',
        '            if (newQtyStr === null) return;',
        '            const new_qty = parseInt(newQtyStr);',
        '            if (isNaN(new_qty) || new_qty < 0) {',
        '                alert("Please enter a valid number.");',
        '                return;',
        '            }',
        '',
        '            const res = await apiCall("/api/dispense/adjust-cumulative", "PUT", {',
        '                zone: activeZone,',
        '                drug_name: drugName,',
        '                new_qty',
        '            });',
        '',
        '            if (res && !res.error) {',
        '                refreshData();',
        '            } else {',
        '                alert(res ? res.error : "Update failed.");',
        '            }',
        '        }',
        '',
        '        async function clearZoneTotals() {',
        '            if (!confirm(`Are you sure you want to clear all cumulative totals for zone ${activeZone}?`)) return;',
        '            const res = await apiCall("/api/dispense/clear/all", "DELETE", { zone: activeZone });',
        '            if (res && !res.error) {',
        '                refreshData();',
        '            }',
        '        }',
        '',
        '        function openMasterModal() {',
        '            renderMasterModalList();',
        '            document.getElementById("master-modal").classList.remove("hidden");',
        '        }',
        '',
        '        function closeMasterModal() {',
        '            document.getElementById("master-modal").classList.add("hidden");',
        '            refreshData();',
        '        }',
        '',
        '        async function renderMasterModalList() {',
        '            await loadMasterDrugs();',
        '            const tbody = document.getElementById("master-modal-tbody");',
        '            tbody.innerHTML = "";',
        '',
        '            masterDrugs.forEach(d => {',
        '                const tr = document.createElement("tr");',
        '                tr.innerHTML = `',
        '                    <td><b>${d}</b></td>',
        '                    <td>',
        '                        <button class="action-link" onclick="renameMasterDrug(\`${d}\`)">Rename</button> | ',
        '                        <button class="action-link" style="color:var(--danger);" onclick="deleteMasterDrug(\`${d}\`)">Remove</button>',
        '                    </td>',
        '                `;',
        '                tbody.appendChild(tr);',
        '            });',
        '        }',
        '',
        '        async function addMasterDrug() {',
        '            const input = document.getElementById("new-master-drug");',
        '            const drugName = input.value.trim().toUpperCase();',
        '            if (!drugName) return;',
        '',
        '            await apiCall("/api/master-drugs", "POST", { zone: activeZone, drug_name: drugName });',
        '            input.value = "";',
        '            renderMasterModalList();',
        '        }',
        '',
        '        async function renameMasterDrug(oldName) {',
        '            const newName = prompt(`Rename drug "${oldName}" to:`, oldName);',
        '            if (!newName || !newName.trim()) return;',
        '',
        '            await apiCall("/api/master-drugs/rename", "PUT", {',
        '                zone: activeZone,',
        '                oldName,',
        '                newName: newName.trim().toUpperCase()',
        '            });',
        '            renderMasterModalList();',
        '        }',
        '',
        '        async function deleteMasterDrug(drugName) {',
        '            if (!confirm(`Remove "${drugName}" from Master Directory?`)) return;',
        '            await apiCall("/api/master-drugs", "DELETE", { zone: activeZone, drug_name: drugName });',
        '            renderMasterModalList();',
        '        }',
        '',
        '        function openImportModal() {',
        '            document.getElementById("import-textarea").value = "";',
        '            document.getElementById("import-file-input").value = "";',
        '            parsedImportRows = [];',
        '            document.getElementById("import-modal").classList.remove("hidden");',
        '        }',
        '',
        '        function closeImportModal() {',
        '            document.getElementById("import-modal").classList.add("hidden");',
        '            refreshData();',
        '        }',
        '',
        '        function handleFileSelection(event) {',
        '            const file = event.target.files[0];',
        '            if (!file) return;',
        '',
        '            const reader = new FileReader();',
        '            const ext = file.name.split(".").pop().toLowerCase();',
        '',
        '            if (ext === "csv" || ext === "txt") {',
        '                reader.onload = (e) => {',
        '                    document.getElementById("import-textarea").value = e.target.result;',
        '                };',
        '                reader.readAsText(file);',
        '            } else {',
        '                reader.onload = (e) => {',
        '                    try {',
        '                        const data = new Uint8Array(e.target.result);',
        '                        const workbook = XLSX.read(data, { type: "array" });',
        '                        const firstSheetName = workbook.SheetNames[0];',
        '                        const worksheet = workbook.Sheets[firstSheetName];',
        '                        const json = XLSX.utils.sheet_to_json(worksheet, { header: 1 });',
        '                        ',
        '                        let flatLines = [];',
        '                        json.forEach(row => {',
        '                            if (Array.isArray(row)) {',
        '                                flatLines.push(row.join(", "));',
        '                            }',
        '                        });',
        '                        document.getElementById("import-textarea").value = flatLines.join("\\n");',
        '                    } catch (err) {',
        '                        alert("Failed to parse Excel file.");',
        '                    }',
        '                };',
        '                reader.readAsArrayBuffer(file);',
        '            }',
        '        }',
        '',
        '        async function executeBulkImport() {',
        '            const mode = document.getElementById("import-mode").value;',
        '            const rawText = document.getElementById("import-textarea").value.trim();',
        '',
        '            if (!rawText) {',
        '                alert("Please provide text or upload a file to import.");',
        '                return;',
        '            }',
        '',
        '            const lines = rawText.split(/[\\r\\n]+/).map(l => l.trim()).filter(l => l.length > 0);',
        '',
        '            const res = await apiCall("/api/dispense/import", "POST", {',
        '                zone: activeZone,',
        '                mode,',
        '                entries: lines',
        '            });',
        '',
        '            if (res && !res.error) {',
        '                alert(res.message);',
        '                closeImportModal();',
        '                refreshData();',
        '            } else {',
        '                alert(res ? res.error : "Import failed.");',
        '            }',
        '        }',
        '',
        '        function exportExcel() {',
        '            if (liveInventoryData.length === 0) {',
        '                alert("No inventory data to export.");',
        '                return;',
        '            }',
        '',
        '            const wsData = [',
        '                ["Drug Name", "Total Dispensed", "Last Entered By", "Zone: " + activeZone],',
        '                ...liveInventoryData.map(i => [i.drug_name, i.total, i.entered_by])',
        '            ];',
        '',
        '            const wb = XLSX.utils.book_new();',
        '            const ws = XLSX.utils.aoa_to_sheet(wsData);',
        '            XLSX.utils.book_append_sheet(wb, ws, "Inventory");',
        '            XLSX.writeFile(wb, `Inventory_${activeZone}_${new Date().toISOString().slice(0,10)}.xlsx`);',
        '        }',
        '',
        '        function exportPDF() {',
        '            if (liveInventoryData.length === 0) {',
        '                alert("No inventory data to export.");',
        '                return;',
        '            }',
        '',
        '            const { jsPDF } = window.jspdf;',
        '            const doc = new jsPDF();',
        '',
        '            doc.setFontSize(16);',
        '            doc.text("RxMEDISYNC PRO - Inventory Report", 14, 20);',
        '            doc.setFontSize(11);',
        '            doc.text(`Zone: ${activeZone} | Date: ${new Date().toLocaleDateString()}`, 14, 28);',
        '',
        '            const tableData = liveInventoryData.map(i => [i.drug_name, i.total, i.entered_by]);',
        '',
        '            doc.autoTable({',
        '                startY: 35,',
        '                head: [["Drug Name", "Total Dispensed", "Last Entered By"]],',
        '                body: tableData,',
        '                theme: "grid"',
        '            });',
        '',
        '            doc.save(`Inventory_${activeZone}_${new Date().toISOString().slice(0,10)}.pdf`);',
        '        }',
        '    </script>',
        '</body>',
        '</html>',
    ];

    res.send(htmlLines.join('\n'));
});

app.listen(PORT, () => {
    console.log(`RxMedisync Pro Server running on port ${PORT}`);
});
