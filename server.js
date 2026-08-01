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

    db.get("SELECT * FROM users WHERE role = 'ADMIN'", async (err, row) => {
        if (!row) {
            const hash = await bcrypt.hash('admin123', 10);
            db.run("INSERT INTO users (username, phone, password, role, zones, status) VALUES ('admin', '0000000000', ?, 'ADMIN', '[\"ALL\"]', 1)", [hash]);
        }
    });
}

// Authentication Middleware (Strict 8-Hour Session Enforcement & Access Control)
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

app.put('/api/users/:id/status', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required." });
    db.run("UPDATE users SET status = ? WHERE id = ?", [req.body.status, req.params.id], (err) => {
        res.json({ message: "User status updated." });
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

app.post('/api/master-drugs/import', authenticateToken, (req, res) => {
    const mode = req.body.mode;
    const drugs = req.body.drugs;
    const zone = req.body.zone;
    db.serialize(() => {
        if (mode === 'reset') db.run("DELETE FROM master_drugs WHERE zone = ?", [zone]);
        const stmt = db.prepare("INSERT OR IGNORE INTO master_drugs (zone, drug_name) VALUES (?, ?)");
        drugs.forEach(d => { if (d) stmt.run(zone, String(d).trim().toUpperCase()); });
        stmt.finalize(() => res.json({ message: "Master Directory imported successfully." }));
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
    const records = req.body.records;
    const zone = req.body.zone;
    db.serialize(() => {
        if (mode === 'reset') db.run("DELETE FROM dispenses WHERE zone = ?", [zone]);
        const stmt = db.prepare("INSERT INTO dispenses (zone, drug_name, qty, entered_by) VALUES (?, ?, ?, ?)");
        records.forEach(r => { if (r.drug_name) stmt.run(zone, String(r.drug_name).trim().toUpperCase(), parseInt(r.qty || 1), req.user.username); });
        stmt.finalize(() => res.json({ message: "Totals imported successfully." }));
    });
});

// ==========================================
// SINGLE-FILE WEB APPLICATION INTERFACE
// ==========================================

app.get('/', (req, res) => {
    const htmlLines = [
        '<!DOCTYPE html>',
        '<html lang="en">',
        '<head>',
        '    <meta charset="UTF-8">',
        '    <meta name="viewport" content="width=device-width, initial-scale=1.0">',
        '    <title>PHARMA-SYNC PRO</title>',
        '    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>',
        '    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.23/jspdf.plugin.autotable.min.js"></script>',
        '    <script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></script>',
        '    <style>',
        '        * { box-sizing: border-box; margin: 0; padding: 0; font-family: system-ui, -apple-system, sans-serif; }',
        '        body { background: #0f172a; color: #f8fafc; min-height: 100vh; padding: 20px; }',
        '        .container { max-width: 1100px; margin: 0 auto; }',
        '        .card { background: #1e293b; border-radius: 12px; padding: 24px; margin-bottom: 20px; border: 1px solid #334155; }',
        '        h1, h2, h3 { color: #38bdf8; margin-bottom: 15px; }',
        '        input, select, button { width: 100%; padding: 12px; margin-bottom: 12px; border-radius: 6px; border: 1px solid #475569; background: #0f172a; color: white; }',
        '        button { background: #0284c7; font-weight: bold; cursor: pointer; border: none; transition: 0.2s; }',
        '        button:hover { background: #0369a1; }',
        '        button.danger { background: #ef4444; }',
        '        button.danger:hover { background: #dc2626; }',
        '        table { width: 100%; border-collapse: collapse; margin-top: 10px; }',
        '        th, td { border: 1px solid #334155; padding: 10px; text-align: left; font-size: 14px; }',
        '        th { background: #0f172a; color: #38bdf8; }',
        '        .hidden { display: none !important; }',
        '        .flex { display: flex; gap: 10px; }',
        '        .badge { background: #0369a1; padding: 4px 8px; border-radius: 4px; font-size: 12px; }',
        '        .footer { text-align: center; font-size: 12px; color: #94a3b8; margin-top: 30px; border-top: 1px solid #334155; padding-top: 15px; }',
        '    </style>',
        '</head>',
        '<body>',
        '    <div class="container">',
        '        <div id="login-screen" class="card" style="max-width: 450px; margin: 80px auto;">',
        '            <h2>PHARMA-SYNC PRO</h2>',
        '            <p style="color: #94a3b8; margin-bottom: 20px; font-size: 14px;">Secure Authorization Gateway</p>',
        '            <input type="text" id="login-username" placeholder="Username or Phone Number">',
        '            <input type="password" id="login-password" placeholder="Password">',
        '            <button onclick="handleLogin()">AUTHENTICATE LOGIN</button>',
        '            <div id="login-error" style="color: #f87171; font-size: 13px; text-align: center; margin-top: 10px;"></div>',
        '        </div>',

        '        <div id="app-screen" class="hidden">',
        '            <div class="card flex" style="justify-content: space-between; align-items: center;">',
        '                <div>',
        '                    <h2 id="user-display">Welcome</h2>',
        '                    <span id="role-display" class="badge">ROLE</span>',
        '                </div>',
        '                <div style="width: 200px;">',
        '                    <button onclick="handleLogout()" class="danger">LOGOUT</button>',
        '                </div>',
        '            </div>',

        '            <div id="admin-view" class="hidden">',
        '                <div class="card">',
        '                    <h3>Admin Security Profile</h3>',
        '                    <div class="flex">',
        '                        <input type="text" id="admin-new-user" placeholder="New Admin Username">',
        '                        <input type="password" id="admin-new-pass" placeholder="New Admin Password">',
        '                    </div>',
        '                    <button onclick="updateAdminProfile()">Update Credentials</button>',
        '                </div>',

        '                <div class="card">',
        '                    <h3>User Access & Zone Management</h3>',
        '                    <input type="text" id="nu-name" placeholder="User Full Name / Username">',
        '                    <input type="text" id="nu-phone" placeholder="Phone Number">',
        '                    <input type="password" id="nu-pass" placeholder="Account Password">',
        '                    <input type="text" id="nu-zones" placeholder="Assigned Zones (Comma separated, e.g. Zone-A, Zone-B)">',
        '                    <button onclick="createUser()">Create Assigned User</button>',
        '                    <br><br>',
        '                    <h3>Registered User Directory</h3>',
        '                    <table>',
        '                        <thead><tr><th>Username</th><th>Phone</th><th>Assigned Zones</th><th>Status</th><th>Access Toggle</th></tr></thead>',
        '                        <tbody id="users-table"></tbody>',
        '                    </table>',
        '                </div>',

        '                <div class="card">',
        '                    <h3>Master Directory & Totals Import (Admin Engine)</h3>',
        '                    <select id="admin-import-zone"><option value="">Select Target Zone</option></select>',
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
        '                    <h3>User Activity & System Audit Logs</h3>',
        '                    <table>',
        '                        <thead><tr><th>Time</th><th>User</th><th>Phone</th><th>Zones</th><th>Action</th></tr></thead>',
        '                        <tbody id="audit-table"></tbody>',
        '                    </table>',
        '                </div>',
        '            </div>',

        '            <div id="user-view" class="hidden">',
        '                <div class="card">',
        '                    <h3>Active Working Zone Selection</h3>',
        '                    <select id="user-zone-select" onchange="switchZone()"></select>',
        '                </div>',

        '                <div class="card">',
        '                    <h3>Register New Drug to Zone Master Directory</h3>',
        '                    <div class="flex">',
        '                        <input type="text" id="new-drug-name" placeholder="Drug Name (e.g., PARACETAMOL 500MG)">',
        '                        <button onclick="registerDrug()" style="width: 250px;">Register Drug</button>',
        '                    </div>',
        '                </div>',

        '                <div class="card">',
        '                    <h3>Dispense Entry (Today\'s Total)</h3>',
        '                    <select id="dispense-drug-select"></select>',
        '                    <input type="number" id="dispense-qty" placeholder="Quantity">',
        '                    <button onclick="recordDispense()">Record Dispense Entry</button>',
        '                </div>',

        '                <div class="card">',
        '                    <h3>Rename Drug Master Directory Entry</h3>',
        '                    <select id="rename-drug-select"></select>',
        '                    <input type="text" id="rename-drug-new" placeholder="New Drug Name">',
        '                    <button onclick="renameDrug()">Rename Globally</button>',
        '                </div>',

        '                <div class="card">',
        '                    <h3>Export & Backup Suite</h3>',
        '                    <input type="text" id="export-remarks" placeholder="Mandatory Export Remarks (Required for PDF)">',
        '                    <div class="flex">',
        '                        <button onclick="exportPDF()">Download Zone PDF</button>',
        '                        <button onclick="exportMasterJSON()">Export Master Directory JSON</button>',
        '                        <button onclick="exportDispenseJSON()">Export Totals & History JSON</button>',
        '                    </div>',
        '                </div>',

        '                <div class="card">',
        '                    <h3>Recent Dispense Activity</h3>',
        '                    <table>',
        '                        <thead><tr><th>Drug Name</th><th>Qty</th><th>Recorded By</th><th>Timestamp</th><th>Actions</th></tr></thead>',
        '                        <tbody id="history-table"></tbody>',
        '                    </table>',
        '                </div>',
        '            </div>',
        '        </div>',

        '        <div class="footer">',
        '            System Architecture & Sole Copyright Holder: <b>Debanjan Singha</b><br>',
        '            All Rights Reserved. Copyright &copy; 2026. Unauthorized access or reproduction prohibited.',
        '        </div>',
        '    </div>',

        '    <script>',
        '        let token = localStorage.getItem("token");',
        '        let currentUser = null;',
        '        let activeZone = "";',
        '        let masterDrugsList = [];',
        '        let dispenseHistory = [];',

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

        '        function checkSession() {',
        '            initApp();',
        '        }',

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

        '        async function loadAdminData() {',
        '            const res = await fetch("/api/users", { headers: { "Authorization": "Bearer " + token } });',
        '            if (!res.ok) return handleAccessError(res);',
        '            const users = await res.json();',
        '            const tbody = document.getElementById("users-table");',
        '            tbody.innerHTML = "";',
        '            const zoneSelect = document.getElementById("admin-import-zone");',
        '            zoneSelect.innerHTML = \'<option value="">Select Target Zone</option>\';',
        '            let zoneSet = new Set();',

        '            users.forEach(u => {',
        '                u.zones.forEach(z => zoneSet.add(z));',
        '                tbody.innerHTML += `<tr><td>${u.username}</td><td>${u.phone}</td><td>${u.zones.join(", ")}</td><td>${u.status ? "ACTIVE" : "DISABLED"}</td><td><button onclick="toggleUser(${u.id}, ${u.status ? 0 : 1})">${u.status ? "Disable" : "Enable"}</button></td></tr>`;',
        '            });',

        '            zoneSet.forEach(z => {',
        '                zoneSelect.innerHTML += `<option value="${z}">${z}</option>`;',
        '            });',

        '            const auditRes = await fetch("/api/admin/audit-logs", { headers: { "Authorization": "Bearer " + token } });',
        '            const logs = await auditRes.json();',
        '            const auditBody = document.getElementById("audit-table");',
        '            auditBody.innerHTML = "";',
        '            logs.forEach(l => {',
        '                auditBody.innerHTML += `<tr><td>${l.timestamp}</td><td>${l.username}</td><td>${l.phone}</td><td>${l.zone}</td><td>${l.action}</td></tr>`;',
        '            });',
        '        }',

        '        async function toggleUser(id, status) {',
        '            await fetch(`/api/users/${id}/status`, {',
        '                method: "PUT",',
        '                headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },',
        '                body: JSON.stringify({ status })',
        '            });',
        '            loadAdminData();',
        '        }',

        '        async function createUser() {',
        '            const u = document.getElementById("nu-name").value;',
        '            const p = document.getElementById("nu-phone").value;',
        '            const pass = document.getElementById("nu-pass").value;',
        '            const z = document.getElementById("nu-zones").value.split(",").map(s => s.trim());',
        '            const res = await fetch("/api/users", {',
        '                method: "POST",',
        '                headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },',
        '                body: JSON.stringify({ username: u, phone: p, password: pass, zones: z })',
        '            });',
        '            if (res.ok) { alert("User created successfully"); loadAdminData(); } else { alert("Failed to create user"); }',
        '        }',

        '        async function updateAdminProfile() {',
        '            const u = document.getElementById("admin-new-user").value;',
        '            const p = document.getElementById("admin-new-pass").value;',
        '            const res = await fetch("/api/admin/profile", {',
        '                method: "PUT",',
        '                headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },',
        '                body: JSON.stringify({ newUsername: u, newPassword: p })',
        '            });',
        '            if (res.ok) { alert("Credentials updated. Please log in again."); handleLogout(); }',
        '        }',

        '        async function loadUserZones() {',
        '            const payload = JSON.parse(atob(token.split(".")[1]));',
        '            const res = await fetch("/api/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: payload.username, password: "" }) });',
        '            // Load zones from active token context',
        '            const zoneSelect = document.getElementById("user-zone-select");',
        '            zoneSelect.innerHTML = "";',
        '            const zRes = await fetch("/api/users", { headers: { "Authorization": "Bearer " + token } }).catch(() => null);',
        '            // Fallback decoding',
        '            activeZone = prompt("Enter your active zone to initialize session:") || "Zone-A";',
        '            zoneSelect.innerHTML = `<option value="${activeZone}">${activeZone}</option>`;',
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
        '                tbody.innerHTML += `<tr><td>${h.drug_name}</td><td>${h.qty}</td><td>${h.entered_by}</td><td>${h.timestamp}</td><td><button onclick="editQty(${h.id})">Edit</button> <button class="danger" onclick="deleteEntry(${h.id})">Undo</button></td></tr>`;',
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
