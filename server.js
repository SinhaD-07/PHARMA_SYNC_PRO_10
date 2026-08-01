const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();

let xlsx;
try {
    xlsx = require('xlsx');
} catch (e) {
    console.log("XLSX package optional check");
}

const app = express();
const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.JWT_SECRET || "pharma_sync_ultra_secure_debanjan_2026_key";

const COPYRIGHT_OWNER = "Debanjan Singha";
console.log("================================================================");
console.log(" PHARMA-SYNC PRO | ALL RIGHTS RESERVED");
console.log(" Proprietary Software Architecture Created by " + COPYRIGHT_OWNER);
console.log("================================================================");

app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Database Initialization
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

    db.get("SELECT * FROM users WHERE role = 'ADMIN'", async (err, row) => {
        if (!row) {
            const hash = await bcrypt.hash('admin123', 10);
            db.run("INSERT INTO users (username, phone, password, role, zones, status) VALUES ('admin', '0000000000', ?, 'ADMIN', '[\"ALL\"]', 1)", [hash]);
        }
    });
}

// Security Middleware (8-Hour Expiry Safeguard)
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Access Denied." });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(403).json({ error: "Session expired." });
        db.get("SELECT * FROM users WHERE id = ?", [decoded.id], (err, user) => {
            if (err || !user) return res.status(404).json({ error: "User not found." });
            if (user.status !== 1) {
                return res.status(403).json({ error: "ACCESS_DISABLED", message: "ERROR! PLEASE CONTACT TO THE ADMIN" });
            }
            req.user = user;
            next();
        });
    });
};

// API ROUTES

app.post('/api/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    if (!username || !password) return res.status(400).json({ error: "Required fields missing" });

    db.get("SELECT * FROM users WHERE username = ? OR phone = ?", [username, username], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: "Invalid credentials" });
        if (user.status !== 1) return res.status(403).json({ error: "ERROR! PLEASE CONTACT TO THE ADMIN" });

        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) return res.status(400).json({ error: "Invalid credentials" });

        db.run("INSERT INTO audit_logs (username, phone, zone, action) VALUES (?, ?, ?, 'LOGIN')", [user.username, user.phone, user.zones]);

        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, SECRET_KEY, { expiresIn: '8h' });
        let userZones = [];
        try { userZones = JSON.parse(user.zones); } catch(e) { userZones = [user.zones]; }

        res.json({ token, role: user.role, username: user.username, phone: user.phone, zones: userZones });
    });
});

app.post('/api/logout', authenticateToken, (req, res) => {
    db.run("INSERT INTO audit_logs (username, phone, zone, action) VALUES (?, ?, ?, 'LOGOUT')", [req.user.username, req.user.phone, req.body.zone || "N/A"]);
    res.json({ message: "Logged out" });
});

app.put('/api/admin/profile', authenticateToken, async (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin required" });
    const newUsername = req.body.newUsername;
    const newPassword = req.body.newPassword;
    if (!newUsername || !newPassword) return res.status(400).json({ error: "Missing parameters" });

    const hash = await bcrypt.hash(newPassword, 10);
    db.run("UPDATE users SET username = ?, password = ? WHERE id = ?", [newUsername.trim(), hash, req.user.id], function(err) {
        if (err) return res.status(500).json({ error: "Username taken" });
        res.json({ message: "Updated successfully" });
    });
});

app.get('/api/users', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin required" });
    db.all("SELECT id, username, phone, role, zones, status FROM users WHERE role != 'ADMIN'", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        const parsedRows = rows.map(r => {
            let z = [];
            try { z = JSON.parse(r.zones); } catch(e) { z = [r.zones]; }
            return { id: r.id, username: r.username, phone: r.phone, role: r.role, zones: z, status: r.status };
        });
        res.json(parsedRows);
    });
});

app.post('/api/users', authenticateToken, async (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin required" });
    const username = req.body.username;
    const phone = req.body.phone;
    const password = req.body.password;
    const zones = req.body.zones;

    const hash = await bcrypt.hash(password, 10);
    db.run("INSERT INTO users (username, phone, password, role, zones, status) VALUES (?, ?, ?, 'OPERATOR', ?, 1)", 
        [username.trim(), phone.trim(), hash, JSON.stringify(zones)], 
        (err) => {
            if (err) return res.status(400).json({ error: "User exists" });
            res.json({ message: "Created" });
        }
    );
});

app.put('/api/users/:id/status', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin required" });
    db.run("UPDATE users SET status = ? WHERE id = ?", [req.body.status, req.params.id], (err) => {
        res.json({ message: "Updated" });
    });
});

app.get('/api/admin/audit-logs', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin required" });
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
        res.json({ message: "Saved" });
    });
});

app.put('/api/master-drugs/rename', authenticateToken, (req, res) => {
    const oldName = req.body.oldName;
    const newName = req.body.newName;
    const zone = req.body.zone;
    db.serialize(() => {
        db.run("UPDATE master_drugs SET drug_name = ? WHERE drug_name = ? AND zone = ?", [newName.trim().toUpperCase(), oldName.trim().toUpperCase(), zone]);
        db.run("UPDATE dispenses SET drug_name = ? WHERE drug_name = ? AND zone = ?", [newName.trim().toUpperCase(), oldName.trim().toUpperCase(), zone], (err) => {
            res.json({ message: "Updated" });
        });
    });
});

app.post('/api/master-drugs/import', authenticateToken, (req, res) => {
    const mode = req.body.mode;
    const drugs = req.body.drugs;
    const zone = req.body.zone;
    db.serialize(() => {
        if (mode === 'reset') db.run("DELETE FROM master_drugs WHERE zone = ?", [zone]);
        const stmt = db.prepare("INSERT OR IGNORE INTO master_drugs (zone, drug_name) VALUES (?, ?)");
        drugs.forEach(d => { if (d) stmt.run(zone, String(d).trim().toUpperCase()); });
        stmt.finalize(() => res.json({ message: "Master directory imported successfully" }));
    });
});

app.post('/api/dispense', authenticateToken, (req, res) => {
    db.run("INSERT INTO dispenses (zone, drug_name, qty, entered_by) VALUES (?, ?, ?, ?)", 
        [req.body.zone, req.body.drug_name.trim().toUpperCase(), parseInt(req.body.qty), req.user.username], 
        () => res.json({ message: "Recorded" })
    );
});

app.get('/api/dispense/sync', authenticateToken, (req, res) => {
    db.all("SELECT * FROM dispenses WHERE zone = ? ORDER BY id DESC LIMIT 500", [req.query.zone], (err, rows) => {
        res.json(rows);
    });
});

app.put('/api/dispense/:id', authenticateToken, (req, res) => {
    db.run("UPDATE dispenses SET qty = ? WHERE id = ?", [parseInt(req.body.qty), req.params.id], () => res.json({ message: "Updated" }));
});

app.delete('/api/dispense/:id', authenticateToken, (req, res) => {
    db.run("DELETE FROM dispenses WHERE id = ?", [req.params.id], () => res.json({ message: "Deleted" }));
});

app.post('/api/dispense/import', authenticateToken, (req, res) => {
    const mode = req.body.mode;
    const records = req.body.records;
    const zone = req.body.zone;
    db.serialize(() => {
        if (mode === 'reset') db.run("DELETE FROM dispenses WHERE zone = ?", [zone]);
        const stmt = db.prepare("INSERT INTO dispenses (zone, drug_name, qty, entered_by) VALUES (?, ?, ?, ?)");
        records.forEach(r => { if (r.drug_name) stmt.run(zone, String(r.drug_name).trim().toUpperCase(), parseInt(r.qty || 1), req.user.username); });
        stmt.finalize(() => res.json({ message: "Dispenses imported successfully" }));
    });
});

// FRONTEND INTERFACE ROUTE
app.get('/', (req, res) => {
    const htmlContent = [
        '<!DOCTYPE html>',
        '<html lang="en">',
        '<head>',
        '    <meta charset="UTF-8">',
        '    <meta name="viewport" content="width=device-width, initial-scale=1.0">',
        '    <title>PHARMA-SYNC PRO | ENTERPRISE SYSTEM</title>',
        '    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>',
        '    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.23/jspdf.plugin.autotable.min.js"></script>',
        '    <script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></script>',
        '    <style>',
        '        body { font-family: system-ui, -apple-system, sans-serif; background: #f0f4f9; padding: 20px; color: #0f172a; }',
        '        .card { background: white; padding: 20px; border-radius: 12px; border: 1px solid #cbd5e1; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); max-width: 600px; margin: 40px auto; text-align: center; }',
        '        h1 { color: #0284c7; margin-bottom: 5px; }',
        '        .badge { background: #e0f2fe; color: #0369a1; padding: 6px 12px; border-radius: 20px; font-weight: bold; font-size: 12px; display: inline-block; margin-bottom: 15px; }',
        '        .footer { margin-top: 20px; font-size: 12px; color: #64748b; border-top: 1px solid #e2e8f0; padding-top: 10px; }',
        '    </style>',
        '</head>',
        '<body>',
        '    <div class="card">',
        '        <h1>PHARMA-SYNC PRO</h1>',
        '        <div class="badge">SYSTEM ONLINE & SECURE</div>',
        '        <p>Full API Backend and Dynamic Directory Engine active.</p>',
        '        <div class="footer">',
        '            Legal Credits & Lead Architecture: <b>Debanjan Singha</b><br>',
        '            All Rights Reserved. Copyright © 2026.',
        '        </div>',
        '    </div>',
        '</body>',
        '</html>'
    ].join('\n');

    res.setHeader('Content-Type', 'text/html');
    res.send(htmlContent);
});

app.listen(PORT, () => {
    console.log("Server running on port " + PORT);
});
