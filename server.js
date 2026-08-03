/**
 * RxMEDISYNC PRO - Complete Enterprise Server & Application
 * Developed by Debanjan Singha
 */

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const helmet = require('helmet');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'rx_medisync_super_secure_secret_key_2026';

// Middleware Setup
app.use(helmet({
    contentSecurityPolicy: false, // Allow inline styles/scripts for single-file app rendering
    crossOriginEmbedderPolicy: false
}));
app.use(compression());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());

// Database Initialization (SQLite with WAL mode for concurrency)
const dbPath = path.join(__dirname, 'rx_medisync.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Database connection error:', err.message);
    } else {
        console.log('Connected to SQLite database.');
        db.run('PRAGMA journal_mode = WAL;');
        db.run('PRAGMA foreign_keys = ON;');
        initDatabase();
    }
});

function initDatabase() {
    db.serialize(() => {
        // Users Table
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'operator',
            zones TEXT DEFAULT '["Main Zone"]',
            status TEXT DEFAULT 'active',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Master Directory Table
        db.run(`CREATE TABLE IF NOT EXISTS master_directory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_code TEXT UNIQUE NOT NULL,
            item_name TEXT NOT NULL,
            category TEXT,
            unit TEXT,
            zone TEXT DEFAULT 'Main Zone',
            stock_qty INTEGER DEFAULT 0,
            unit_price REAL DEFAULT 0.0,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Transaction Audit Logs Table
        db.run(`CREATE TABLE IF NOT EXISTS transaction_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            username TEXT,
            action TEXT,
            details TEXT,
            zone TEXT
        )`);

        // User Login/Logout Activity Tracker Table
        db.run(`CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            username TEXT,
            activity_type TEXT,
            ip_address TEXT
        )`);

        // Seed Default Admin if none exists
        db.get(`SELECT COUNT(*) as count FROM users`, async (err, row) => {
            if (row && row.count === 0) {
                const hashedPassword = await bcrypt.hash('admin123', 10);
                db.run(`INSERT INTO users (username, password, role, zones, status) VALUES (?, ?, ?, ?, ?)`,
                    ['admin', hashedPassword, 'admin', JSON.stringify(['All Zones', 'Main Zone']), 'active'],
                    (err) => {
                        if (!err) console.log('Default admin account created: admin / admin123');
                    }
                );
            }
        });
    });
}

// Authentication Middleware
function authenticateToken(req, res, next) {
    const token = req.cookies.token || req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Authentication required. Please login.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Session expired or invalid token.' });
        req.user = user;
        next();
    });
}

function requireAdmin(req, res, next) {
    if (!req.user || req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access denied. Administrator privileges required.' });
    }
    next();
}

// --- API ROUTES ---

// Login Endpoint
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password are required.' });

    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: 'Invalid username or password.' });
        if (user.status !== 'active') return res.status(403).json({ error: 'Account is deactivated. Contact Administrator.' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Invalid username or password.' });

        const tokenPayload = { id: user.id, username: user.username, role: user.role, zones: JSON.parse(user.zones || '[]') };
        const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '8h' });

        // Log Activity
        const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        db.run(`INSERT INTO activity_logs (username, activity_type, ip_address) VALUES (?, ?, ?)`,
            [user.username, 'LOGIN', clientIp]);

        res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', maxAge: 28800000 });
        res.json({ message: 'Login successful', user: tokenPayload });
    });
});

// Logout Endpoint
app.post('/api/logout', authenticateToken, (req, res) => {
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    db.run(`INSERT INTO activity_logs (username, activity_type, ip_address) VALUES (?, ?, ?)`,
        [req.user.username, 'LOGOUT', clientIp]);

    res.clearCookie('token');
    res.json({ message: 'Logged out successfully' });
});

// Get Master Directory Items
app.get('/api/inventory', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM master_directory ORDER BY updated_at DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// Add / Update Inventory Item
app.post('/api/inventory', authenticateToken, (req, res) => {
    const { item_code, item_name, category, unit, zone, stock_qty, unit_price } = req.body;
    if (!item_code || !item_name) return res.status(400).json({ error: 'Item code and name are required.' });

    db.run(`INSERT INTO master_directory (item_code, item_name, category, unit, zone, stock_qty, unit_price, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(item_code) DO UPDATE SET
        item_name = excluded.item_name, category = excluded.category, unit = excluded.unit,
        zone = excluded.zone, stock_qty = excluded.stock_qty, unit_price = excluded.unit_price, updated_at = CURRENT_TIMESTAMP`,
        [item_code, item_name, category, unit, zone || 'Main Zone', stock_qty || 0, unit_price || 0.0],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });

            // Log Transaction
            db.run(`INSERT INTO transaction_logs (username, action, details, zone) VALUES (?, ?, ?, ?)`,
                [req.user.username, 'SAVE_ITEM', `Saved item: ${item_code} - ${item_name}`, zone || 'Main Zone']);

            res.json({ message: 'Item saved successfully', id: this.lastID });
        }
    );
});

// --- ADMIN API ROUTES ---

// Get All Users
app.get('/api/admin/users', authenticateToken, requireAdmin, (req, res) => {
    db.all(`SELECT id, username, role, zones, status, created_at FROM users`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        const parsedRows = rows.map(u => ({ ...u, zones: JSON.parse(u.zones || '[]') }));
        res.json(parsedRows);
    });
});

// Create User
app.post('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    const { username, password, role, zones } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required.' });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const zoneArrayJson = JSON.stringify(zones || ['Main Zone']);
        db.run(`INSERT INTO users (username, password, role, zones, status) VALUES (?, ?, ?, ?, 'active')`,
            [username, hashedPassword, role || 'operator', zoneArrayJson],
            function(err) {
                if (err) return res.status(400).json({ error: 'Username already exists or database error.' });
                res.json({ message: 'User created successfully', id: this.lastID });
            }
        );
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Toggle User Status (Disable / Enable)
app.patch('/api/admin/users/:id/status', authenticateToken, requireAdmin, (req, res) => {
    const { status } = req.body;
    db.run(`UPDATE users SET status = ? WHERE id = ?`, [status, req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'User status updated successfully' });
    });
});

// Delete User
app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, (req, res) => {
    db.run(`DELETE FROM users WHERE id = ? AND id != 1`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'User deleted successfully' });
    });
});

// --- NEW FEATURE 3: EDIT ZONES ENDPOINT ---
app.put('/api/admin/users/:id/zones', authenticateToken, requireAdmin, (req, res) => {
    const { zones } = req.body;
    if (!Array.isArray(zones)) return res.status(400).json({ error: 'Zones must be provided as an array.' });

    const zonesJson = JSON.stringify(zones);
    db.run(`UPDATE users SET zones = ? WHERE id = ?`, [zonesJson, req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'User zones updated successfully', zones });
    });
});

// Get Transaction Audit Logs
app.get('/api/admin/audit-logs', authenticateToken, requireAdmin, (req, res) => {
    db.all(`SELECT * FROM transaction_logs ORDER BY timestamp DESC LIMIT 500`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// --- NEW FEATURE 2A: DELETE / CLEAR TRANSACTION AUDIT LOGS ---
app.delete('/api/admin/audit-logs', authenticateToken, requireAdmin, (req, res) => {
    db.run(`DELETE FROM transaction_logs`, [], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Transaction audit logs cleared successfully.' });
    });
});

// Get User Login / Logout Activity Tracker Logs
app.get('/api/admin/activity-logs', authenticateToken, requireAdmin, (req, res) => {
    db.all(`SELECT * FROM activity_logs ORDER BY timestamp DESC LIMIT 500`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// --- NEW FEATURE 2B: DELETE / CLEAR ACTIVITY TRACKER LOGS ---
app.delete('/api/admin/activity-logs', authenticateToken, requireAdmin, (req, res) => {
    db.run(`DELETE FROM activity_logs`, [], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Activity tracker logs cleared successfully.' });
    });
});


// --- FRONTEND SINGLE-PAGE INTERFACE ---
app.get('*', (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RxMEDISYNC PRO - Enterprise Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        brand: { 50: '#eef2ff', 500: '#6366f1', 600: '#4f46e5', 700: '#4338ca' }
                    }
                }
            }
        }
    </script>
</head>
<body class="bg-slate-50 text-slate-800 font-sans antialiased min-h-screen flex flex-col">

    <!-- App Header -->
    <header class="bg-white border-b border-slate-200 sticky top-0 z-30 shadow-sm">
        <div class="max-w-7xl mx-auto px-4 py-3 flex justify-between items-center">
            <div class="flex items-center space-x-3">
                <div class="bg-gradient-to-tr from-indigo-600 to-violet-500 text-white p-2.5 rounded-xl shadow-md">
                    <i class="fa-solid fa-pills text-xl"></i>
                </div>
                <div>
                    <h1 class="font-bold text-lg text-slate-900 tracking-tight">RxMEDISYNC PRO</h1>
                    <p class="text-xs text-slate-500">Multi-Zone Enterprise Management</p>
                </div>
            </div>
            
            <div id="userHeaderSection" class="hidden flex items-center space-x-4">
                <span id="welcomeUserText" class="text-sm font-medium text-slate-700"></span>
                
                <!-- NEW FEATURE 1: Resolved Quick Utility / Refresh Button Beside Logout -->
                <button onclick="refreshDashboardData()" title="Quick Refresh Data" class="p-2 text-slate-500 hover:text-indigo-600 hover:bg-indigo-50 rounded-lg transition-colors border border-slate-200 shadow-sm">
                    <i class="fa-solid fa-rotate"></i>
                </button>

                <button onclick="logoutUser()" class="flex items-center space-x-1.5 px-3.5 py-2 bg-rose-50 text-rose-600 hover:bg-rose-100 rounded-lg font-medium text-sm transition-colors shadow-sm">
                    <i class="fa-solid fa-power-off"></i>
                    <span>Logout</span>
                </button>
            </div>
        </div>
    </header>

    <!-- Main App Container -->
    <main class="flex-1 max-w-7xl w-full mx-auto px-4 py-6">

        <!-- Login Card View -->
        <div id="loginView" class="max-w-md mx-auto mt-16 bg-white p-8 rounded-2xl shadow-xl border border-slate-100">
            <div class="text-center mb-8">
                <div class="inline-block p-3 bg-indigo-50 text-indigo-600 rounded-2xl mb-3 shadow-inner">
                    <i class="fa-solid fa-shield-halved text-3xl"></i>
                </div>
                <h2 class="text-2xl font-bold text-slate-900">Welcome Back</h2>
                <p class="text-sm text-slate-500">Sign in to access your administrative dashboard</p>
            </div>

            <form id="loginForm" onsubmit="handleLogin(event)" class="space-y-4">
                <div>
                    <label class="block text-xs font-semibold uppercase tracking-wider text-slate-600 mb-1">Username</label>
                    <input type="text" id="loginUsername" required class="w-full px-4 py-2.5 rounded-xl border border-slate-300 focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none transition-all">
                </div>
                <div>
                    <label class="block text-xs font-semibold uppercase tracking-wider text-slate-600 mb-1">Password</label>
                    <input type="password" id="loginPassword" required class="w-full px-4 py-2.5 rounded-xl border border-slate-300 focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none transition-all">
                </div>
                <div id="loginError" class="text-rose-500 text-sm hidden font-medium text-center"></div>
                <button type="submit" class="w-full py-3 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold rounded-xl shadow-lg shadow-indigo-200 transition-all">
                    Sign In
                </button>
            </form>
        </div>

        <!-- Dashboard View -->
        <div id="dashboardView" class="hidden space-y-6">
            
            <!-- Admin Navigation Tabs -->
            <div id="adminNavTabs" class="hidden flex space-x-2 border-b border-slate-200 pb-3">
                <button onclick="switchTab('inventoryTab')" id="tabBtnInventory" class="px-4 py-2 rounded-xl font-medium text-sm bg-indigo-600 text-white shadow-sm transition-all">
                    <i class="fa-solid fa-boxes-stacked mr-2"></i> Master Inventory
                </button>
                <button onclick="switchTab('usersTab')" id="tabBtnUsers" class="px-4 py-2 rounded-xl font-medium text-sm text-slate-600 hover:bg-slate-200 transition-all">
                    <i class="fa-solid fa-users-gear mr-2"></i> Operator & Zone Control
                </button>
                <button onclick="switchTab('logsTab')" id="tabBtnLogs" class="px-4 py-2 rounded-xl font-medium text-sm text-slate-600 hover:bg-slate-200 transition-all">
                    <i class="fa-solid fa-clipboard-list mr-2"></i> Audit & Activity Trackers
                </button>
            </div>

            <!-- Tab 1: Inventory -->
            <div id="inventoryTab" class="space-y-4">
                <div class="bg-white p-6 rounded-2xl shadow-sm border border-slate-200 flex justify-between items-center">
                    <div>
                        <h3 class="text-lg font-bold text-slate-900">Master Directory Inventory</h3>
                        <p class="text-xs text-slate-500">Manage multi-zone pharmaceutical stock and asset records</p>
                    </div>
                    <button onclick="loadInventory()" class="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 font-medium text-sm rounded-xl transition-colors">
                        <i class="fa-solid fa-rotate-right mr-1.5"></i> Refresh List
                    </button>
                </div>
                <div class="bg-white rounded-2xl shadow-sm border border-slate-200 overflow-hidden">
                    <table class="w-full text-left border-collapse">
                        <thead>
                            <tr class="bg-slate-50 border-b border-slate-200 text-xs font-bold uppercase tracking-wider text-slate-600">
                                <th class="p-4">Item Code</th>
                                <th class="p-4">Item Name</th>
                                <th class="p-4">Category</th>
                                <th class="p-4">Zone</th>
                                <th class="p-4">Stock Qty</th>
                                <th class="p-4">Unit Price</th>
                            </tr>
                        </thead>
                        <tbody id="inventoryTableBody" class="divide-y divide-slate-100 text-sm">
                            <!-- Dynamic Content -->
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Tab 2: Users & Zone Management -->
            <div id="usersTab" class="hidden space-y-4">
                <div class="bg-white p-6 rounded-2xl shadow-sm border border-slate-200 flex justify-between items-center">
                    <div>
                        <h3 class="text-lg font-bold text-slate-900">Operator & Zone Assignments</h3>
                        <p class="text-xs text-slate-500">Control system users, permissions, and active operating zones</p>
                    </div>
                    <button onclick="openCreateUserModal()" class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white font-medium text-sm rounded-xl shadow-md transition-all">
                        <i class="fa-solid fa-user-plus mr-1.5"></i> Add New Operator
                    </button>
                </div>

                <div class="bg-white rounded-2xl shadow-sm border border-slate-200 overflow-hidden">
                    <table class="w-full text-left border-collapse">
                        <thead>
                            <tr class="bg-slate-50 border-b border-slate-200 text-xs font-bold uppercase tracking-wider text-slate-600">
                                <th class="p-4">Username</th>
                                <th class="p-4">Role</th>
                                <th class="p-4">Assigned Zones</th>
                                <th class="p-4">Status</th>
                                <th class="p-4 text-right">Actions</th>
                            </tr>
                        </thead>
                        <tbody id="usersTableBody" class="divide-y divide-slate-100 text-sm">
                            <!-- Dynamic Content -->
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Tab 3: Audit & Activity Trackers -->
            <div id="logsTab" class="hidden space-y-6">
                
                <!-- Tracker 1: Transaction Audit Logs -->
                <div class="bg-white p-6 rounded-2xl shadow-sm border border-slate-200 space-y-4">
                    <div class="flex justify-between items-center">
                        <div>
                            <h3 class="text-lg font-bold text-slate-900"><i class="fa-solid fa-file-invoice text-indigo-600 mr-2"></i>Transaction Audit Logs</h3>
                            <p class="text-xs text-slate-500">Complete historical audit trail of system transactions and modifications</p>
                        </div>
                        <!-- NEW FEATURE 2: Delete Button for Transaction Logs -->
                        <button onclick="clearLogs('audit')" class="px-3.5 py-2 bg-rose-50 hover:bg-rose-100 text-rose-600 font-medium text-xs rounded-xl transition-colors border border-rose-200 shadow-sm flex items-center space-x-1.5">
                            <i class="fa-solid fa-trash-can"></i>
                            <span>Clear Transaction Logs</span>
                        </button>
                    </div>
                    <div class="overflow-hidden border border-slate-200 rounded-xl max-h-72 overflow-y-auto">
                        <table class="w-full text-left border-collapse">
                            <thead>
                                <tr class="bg-slate-50 border-b border-slate-200 text-xs font-bold uppercase tracking-wider text-slate-600">
                                    <th class="p-3">Timestamp</th>
                                    <th class="p-3">User</th>
                                    <th class="p-3">Action</th>
                                    <th class="p-3">Details</th>
                                    <th class="p-3">Zone</th>
                                </tr>
                            </thead>
                            <tbody id="auditLogsTableBody" class="divide-y divide-slate-100 text-xs"></tbody>
                        </table>
                    </div>
                </div>

                <!-- Tracker 2: User Login / Logout Activity Tracker -->
                <div class="bg-white p-6 rounded-2xl shadow-sm border border-slate-200 space-y-4">
                    <div class="flex justify-between items-center">
                        <div>
                            <h3 class="text-lg font-bold text-slate-900"><i class="fa-solid fa-right-to-bracket text-emerald-600 mr-2"></i>User Login / Logout Activity Tracker</h3>
                            <p class="text-xs text-slate-500">Monitor operator authentication sessions and client connection endpoints</p>
                        </div>
                        <!-- NEW FEATURE 2: Delete Button for Activity Tracker -->
                        <button onclick="clearLogs('activity')" class="px-3.5 py-2 bg-rose-50 hover:bg-rose-100 text-rose-600 font-medium text-xs rounded-xl transition-colors border border-rose-200 shadow-sm flex items-center space-x-1.5">
                            <i class="fa-solid fa-trash-can"></i>
                            <span>Clear Activity Logs</span>
                        </button>
                    </div>
                    <div class="overflow-hidden border border-slate-200 rounded-xl max-h-72 overflow-y-auto">
                        <table class="w-full text-left border-collapse">
                            <thead>
                                <tr class="bg-slate-50 border-b border-slate-200 text-xs font-bold uppercase tracking-wider text-slate-600">
                                    <th class="p-3">Timestamp</th>
                                    <th class="p-3">Username</th>
                                    <th class="p-3">Activity Type</th>
                                    <th class="p-3">IP Address</th>
                                </tr>
                            </thead>
                            <tbody id="activityLogsTableBody" class="divide-y divide-slate-100 text-xs"></tbody>
                        </table>
                    </div>
                </div>

            </div>

        </div>

    </main>

    <!-- NEW FEATURE 3: Edit Zones Modal -->
    <div id="editZonesModal" class="fixed inset-0 bg-slate-900/50 backdrop-blur-sm hidden items-center justify-center z-50 p-4">
        <div class="bg-white rounded-2xl shadow-2xl max-w-md w-full p-6 space-y-4 border border-slate-100">
            <h3 class="text-lg font-bold text-slate-900">Edit Operator Zones</h3>
            <p class="text-xs text-slate-500">Specify authorized operational zones for user: <span id="editZoneUsername" class="font-bold text-indigo-600"></span></p>
            <input type="hidden" id="editZoneUserId">
            <div class="space-y-2">
                <label class="block text-xs font-semibold uppercase tracking-wider text-slate-600">Enter Zones (Comma separated)</label>
                <input type="text" id="editZonesInput" class="w-full px-4 py-2.5 rounded-xl border border-slate-300 focus:ring-2 focus:ring-indigo-500 outline-none text-sm" placeholder="Main Zone, North Wing, Central Hub">
            </div>
            <div class="flex justify-end space-x-3 pt-3 border-t border-slate-100">
                <button onclick="closeEditZonesModal()" class="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 font-medium text-sm rounded-xl">Cancel</button>
                <button onclick="submitEditZones()" class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-sm rounded-xl shadow-md">Save Zones</button>
            </div>
        </div>
    </div>

    <!-- Create User Modal -->
    <div id="createUserModal" class="fixed inset-0 bg-slate-900/50 backdrop-blur-sm hidden items-center justify-center z-50 p-4">
        <div class="bg-white rounded-2xl shadow-2xl max-w-md w-full p-6 space-y-4 border border-slate-100">
            <h3 class="text-lg font-bold text-slate-900">Create New Operator</h3>
            <form onsubmit="handleCreateUser(event)" class="space-y-3">
                <div>
                    <label class="block text-xs font-semibold uppercase tracking-wider text-slate-600 mb-1">Username</label>
                    <input type="text" id="newUsername" required class="w-full px-4 py-2.5 rounded-xl border border-slate-300 focus:ring-2 focus:ring-indigo-500 outline-none text-sm">
                </div>
                <div>
                    <label class="block text-xs font-semibold uppercase tracking-wider text-slate-600 mb-1">Password</label>
                    <input type="password" id="newPassword" required class="w-full px-4 py-2.5 rounded-xl border border-slate-300 focus:ring-2 focus:ring-indigo-500 outline-none text-sm">
                </div>
                <div>
                    <label class="block text-xs font-semibold uppercase tracking-wider text-slate-600 mb-1">Role</label>
                    <select id="newRole" class="w-full px-4 py-2.5 rounded-xl border border-slate-300 focus:ring-2 focus:ring-indigo-500 outline-none text-sm bg-white">
                        <option value="operator">Operator</option>
                        <option value="admin">Administrator</option>
                    </select>
                </div>
                <div>
                    <label class="block text-xs font-semibold uppercase tracking-wider text-slate-600 mb-1">Zones (Comma separated)</label>
                    <input type="text" id="newZones" value="Main Zone" class="w-full px-4 py-2.5 rounded-xl border border-slate-300 focus:ring-2 focus:ring-indigo-500 outline-none text-sm">
                </div>
                <div class="flex justify-end space-x-3 pt-3 border-t border-slate-100">
                    <button type="button" onclick="closeCreateUserModal()" class="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 font-medium text-sm rounded-xl">Cancel</button>
                    <button type="submit" class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-sm rounded-xl shadow-md">Create</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Core Frontend Application Logic -->
    <script>
        let currentUser = null;

        function checkAuthOnLoad() {
            const storedUser = localStorage.getItem('rx_user');
            if (storedUser) {
                currentUser = JSON.parse(storedUser);
                showDashboard();
            }
        }

        async function handleLogin(e) {
            e.preventDefault();
            const username = document.getElementById('loginUsername').value;
            const password = document.getElementById('loginPassword').value;
            const errDiv = document.getElementById('loginError');

            try {
                const res = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error);

                currentUser = data.user;
                localStorage.setItem('rx_user', JSON.stringify(currentUser));
                showDashboard();
            } catch (err) {
                errDiv.textContent = err.message;
                errDiv.classList.remove('hidden');
            }
        }

        async function logoutUser() {
            await fetch('/api/logout', { method: 'POST' });
            localStorage.removeItem('rx_user');
            window.location.reload();
        }

        function showDashboard() {
            document.getElementById('loginView').classList.add('hidden');
            document.getElementById('userHeaderSection').classList.remove('hidden');
            document.getElementById('dashboardView').classList.remove('hidden');
            document.getElementById('welcomeUserText').textContent = \`Signed in as: \${currentUser.username} (\${currentUser.role})\`;

            if (currentUser.role === 'admin') {
                document.getElementById('adminNavTabs').classList.remove('hidden');
                loadAdminData();
            }
            loadInventory();
        }

        function switchTab(tabId) {
            ['inventoryTab', 'usersTab', 'logsTab'].forEach(id => {
                document.getElementById(id).classList.add('hidden');
            });
            ['tabBtnInventory', 'tabBtnUsers', 'tabBtnLogs'].forEach(id => {
                const btn = document.getElementById(id);
                btn.className = 'px-4 py-2 rounded-xl font-medium text-sm text-slate-600 hover:bg-slate-200 transition-all';
            });

            document.getElementById(tabId).classList.remove('hidden');
            const activeBtnMap = { 'inventoryTab': 'tabBtnInventory', 'usersTab': 'tabBtnUsers', 'logsTab': 'tabBtnLogs' };
            document.getElementById(activeBtnMap[tabId]).className = 'px-4 py-2 rounded-xl font-medium text-sm bg-indigo-600 text-white shadow-sm transition-all';
        }

        async function refreshDashboardData() {
            await loadInventory();
            if (currentUser && currentUser.role === 'admin') {
                await loadAdminData();
            }
            alert('Dashboard data refreshed successfully!');
        }

        async function loadInventory() {
            try {
                const res = await fetch('/api/inventory');
                const items = await res.json();
                const tbody = document.getElementById('inventoryTableBody');
                tbody.innerHTML = items.length === 0 ? \`<tr><td colspan="6" class="p-6 text-center text-slate-400">No items available in directory.</td></tr>\` :
                    items.map(i => \`
                        <tr class="hover:bg-slate-50 transition-colors border-b border-slate-100">
                            <td class="p-4 font-mono font-semibold text-indigo-600">\${i.item_code}</td>
                            <td class="p-4 font-medium text-slate-900">\${i.item_name}</td>
                            <td class="p-4 text-slate-600">\${i.category || '-'}</td>
                            <td class="p-4"><span class="px-2.5 py-1 bg-indigo-50 text-indigo-700 text-xs font-semibold rounded-lg">\${i.zone}</span></td>
                            <td class="p-4 font-bold text-slate-700">\${i.stock_qty} \${i.unit || ''}</td>
                            <td class="p-4 font-semibold text-emerald-600">$\${Number(i.unit_price).toFixed(2)}</td>
                        </tr>
                    \`).join('');
            } catch (e) { console.error(e); }
        }

        async function loadAdminData() {
            await loadUsers();
            await loadAuditLogs();
            await loadActivityLogs();
        }

        async function loadUsers() {
            const res = await fetch('/api/admin/users');
            const users = await res.json();
            const tbody = document.getElementById('usersTableBody');
            tbody.innerHTML = users.map(u => \`
                <tr class="hover:bg-slate-50 transition-colors border-b border-slate-100">
                    <td class="p-4 font-semibold text-slate-900">\${u.username}</td>
                    <td class="p-4"><span class="px-2.5 py-1 bg-slate-100 text-slate-700 text-xs font-bold rounded-lg uppercase">\${u.role}</span></td>
                    <td class="p-4 text-xs font-medium text-slate-600">\${u.zones.join(', ')}</td>
                    <td class="p-4"><span class="px-2.5 py-1 \${u.status === 'active' ? 'bg-emerald-50 text-emerald-700' : 'bg-rose-50 text-rose-700'} text-xs font-semibold rounded-lg">\${u.status}</span></td>
                    <td class="p-4 text-right space-x-2">
                        <button onclick="openEditZonesModal(\${u.id}, '\${u.username}', '\${u.zones.join(', ')}')" class="px-3 py-1.5 bg-indigo-50 hover:bg-indigo-100 text-indigo-600 font-medium text-xs rounded-lg transition-colors">Edit Zones</button>
                        <button onclick="toggleUserStatus(\${u.id}, '\${u.status === 'active' ? 'inactive' : 'active'}')" class="px-3 py-1.5 \${u.status === 'active' ? 'bg-amber-50 text-amber-700 hover:bg-amber-100' : 'bg-emerald-50 text-emerald-700 hover:bg-emerald-100'} font-medium text-xs rounded-lg transition-colors">\${u.status === 'active' ? 'Disable' : 'Enable'}</button>
                        <button onclick="deleteUser(\${u.id})" class="px-3 py-1.5 bg-rose-50 hover:bg-rose-100 text-rose-600 font-medium text-xs rounded-lg transition-colors">Delete</button>
                    </td>
                </tr>
            \`).join('');
        }

        async function loadAuditLogs() {
            const res = await fetch('/api/admin/audit-logs');
            const logs = await res.json();
            document.getElementById('auditLogsTableBody').innerHTML = logs.length === 0 ? `<tr><td colspan="5" class="p-4 text-center text-slate-400">No transaction logs available.</td></tr>` :
                logs.map(l => \`
                    <tr class="hover:bg-slate-50 border-b border-slate-100">
                        <td class="p-3 text-slate-500">\${l.timestamp}</td>
                        <td class="p-3 font-semibold text-slate-800">\${l.username}</td>
                        <td class="p-3 text-indigo-600 font-medium">\${l.action}</td>
                        <td class="p-3 text-slate-600">\${l.details}</td>
                        <td class="p-3 text-slate-500">\${l.zone}</td>
                    </tr>
                \`).join('');
        }

        async function loadActivityLogs() {
            const res = await fetch('/api/admin/activity-logs');
            const logs = await res.json();
            document.getElementById('activityLogsTableBody').innerHTML = logs.length === 0 ? `<tr><td colspan="4" class="p-4 text-center text-slate-400">No activity logs available.</td></tr>` :
                logs.map(l => \`
                    <tr class="hover:bg-slate-50 border-b border-slate-100">
                        <td class="p-3 text-slate-500">\${l.timestamp}</td>
                        <td class="p-3 font-semibold text-slate-800">\${l.username}</td>
                        <td class="p-3 font-bold \${l.activity_type === 'LOGIN' ? 'text-emerald-600' : 'text-rose-600'}">\${l.activity_type}</td>
                        <td class="p-3 text-slate-500 font-mono">\${l.ip_address || '127.0.0.1'}</td>
                    </tr>
                \`).join('');
        }

        // NEW FEATURE 2: Clear / Delete Logs Handler
        async function clearLogs(type) {
            if (!confirm(actionConfirmationText(type))) return;
            const endpoint = type === 'audit' ? '/api/admin/audit-logs' : '/api/admin/activity-logs';
            const res = await fetch(endpoint, { method: 'DELETE' });
            if (res.ok) {
                alert('Logs cleared successfully.');
                type === 'audit' ? loadAuditLogs() : loadActivityLogs();
            } else {
                alert('Failed to clear logs.');
            }
        }

        function actionConfirmationText(type) {
            return type === 'audit' ? 'Are you sure you want to permanently clear all Transaction Audit Logs?' : 'Are you sure you want to permanently clear all User Activity Logs?';
        }

        // NEW FEATURE 3: Edit Zones Modal Controls
        function openEditZonesModal(id, username, zones) {
            document.getElementById('editZoneUserId').value = id;
            document.getElementById('editZoneUsername').textContent = username;
            document.getElementById('editZonesInput').value = zones;
            document.getElementById('editZonesModal').classList.remove('hidden');
            document.getElementById('editZonesModal').classList.add('flex');
        }

        function closeEditZonesModal() {
            document.getElementById('editZonesModal').classList.remove('flex');
            document.getElementById('editZonesModal').classList.add('hidden');
        }

        async function submitEditZones() {
            const id = document.getElementById('editZoneUserId').value;
            const zonesRaw = document.getElementById('editZonesInput').value;
            const zones = zonesRaw.split(',').map(z => z.trim()).filter(z => z.length > 0);

            const res = await fetch(\`/api/admin/users/\${id}/zones\`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ zones })
            });

            if (res.ok) {
                alert('User zones updated successfully!');
                closeEditZonesModal();
                loadUsers();
            } else {
                alert('Error updating user zones.');
            }
        }

        function openCreateUserModal() {
            document.getElementById('createUserModal').classList.remove('hidden');
            document.getElementById('createUserModal').classList.add('flex');
        }

        function closeCreateUserModal() {
            document.getElementById('createUserModal').classList.remove('flex');
            document.getElementById('createUserModal').classList.add('hidden');
        }

        async function handleCreateUser(e) {
            e.preventDefault();
            const username = document.getElementById('newUsername').value;
            const password = document.getElementById('newPassword').value;
            const role = document.getElementById('newRole').value;
            const zones = document.getElementById('newZones').value.split(',').map(z => z.trim());

            const res = await fetch('/api/admin/users', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password, role, zones })
            });

            if (res.ok) {
                alert('Operator created successfully!');
                closeCreateUserModal();
                loadUsers();
            } else {
                const data = await res.json();
                alert(data.error || 'Failed to create operator.');
            }
        }

        async function toggleUserStatus(id, newStatus) {
            const res = await fetch(\`/api/admin/users/\${id}/status\`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status: newStatus })
            });
            if (res.ok) loadUsers();
        }

        async function deleteUser(id) {
            if (!confirm('Are you sure you want to delete this user?')) return;
            const res = await fetch(\`/api/admin/users/\${id}\`, { method: 'DELETE' });
            if (res.ok) loadUsers();
        }

        window.onload = checkAuthOnLoad;
    </script>
</body>
</html>`);
});

// Start Server
app.listen(PORT, () => {
    console.log(`RxMEDISYNC PRO running on port ${PORT} by Debanjan Singha`);
});
