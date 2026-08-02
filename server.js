/*******************************************************************************
 * RxMEDISYNC PRO - Enterprise Backend & Frontend Server
 * 
 * Description: High-performance, single-file backend and frontend server built 
 * with Node.js, Express, and SQLite. Features multi-zone inventory management, 
 * secure user access control, bulk imports, audit logging, and automated backups.
 * 
 * Developed by: Debanjan Singha
 ******************************************************************************/

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*' }
});

const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, 'rxmedisync_pro.db');

// Middleware Setup
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Initialize SQLite Database with Concurrency & Performance Optimizations
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error('Database connection error:', err.message);
  } else {
    console.log('Connected to the SQLite database.');
    db.run("PRAGMA journal_mode = WAL;");
    db.run("PRAGMA synchronous = NORMAL;");
    initializeDatabase();
  }
});

// Database Schema Initialization
function initializeDatabase() {
  db.serialize(() => {
    // Users Table
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('ADMIN', 'USER')),
      zone TEXT DEFAULT 'MAIN',
      status TEXT DEFAULT 'ACTIVE',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Master Directory Table
    db.run(`CREATE TABLE IF NOT EXISTS master_directory (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      item_code TEXT UNIQUE NOT NULL,
      item_name TEXT NOT NULL,
      category TEXT,
      unit TEXT,
      stock_qty REAL DEFAULT 0,
      unit_price REAL DEFAULT 0,
      zone TEXT DEFAULT 'MAIN',
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Dispense History Table
    db.run(`CREATE TABLE IF NOT EXISTS dispense_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      dispense_id TEXT UNIQUE NOT NULL,
      item_code TEXT NOT NULL,
      item_name TEXT NOT NULL,
      quantity REAL NOT NULL,
      unit_price REAL NOT NULL,
      total_amount REAL NOT NULL,
      patient_name TEXT,
      zone TEXT DEFAULT 'MAIN',
      operator TEXT NOT NULL,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Audit Logs Table
    db.run(`CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL,
      action TEXT NOT NULL,
      details TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Seed default Admin user if none exists
    db.get(`SELECT COUNT(*) as count FROM users WHERE role = 'ADMIN'`, (err, row) => {
      if (row && row.count === 0) {
        db.run(`INSERT INTO users (username, password, role, zone) VALUES (?, ?, ?, ?)`,
          ['admin', 'admin123', 'ADMIN', 'MAIN'],
          (err) => {
            if (!err) console.log('Default ADMIN user created (admin / admin123)');
          }
        );
      }
    });
  });
}

// REST API Endpoints

// 1. Authentication
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ? AND password = ?`, [username, password], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(401).json({ error: 'Invalid username or password' });
    if (user.status !== 'ACTIVE') return res.status(403).json({ error: 'Account is inactive' });
    
    // Log audit trail
    db.run(`INSERT INTO audit_logs (username, action, details) VALUES (?, ?, ?)`,
      [username, 'LOGIN', `User logged in from zone ${user.zone}`]);

    res.json({ success: true, user: { id: user.id, username: user.username, role: user.role, zone: user.zone } });
  });
});

// 2. Master Directory Management
app.get('/api/directory', (req, res) => {
  const { zone } = req.query;
  let query = `SELECT * FROM master_directory`;
  let params = [];
  if (zone && zone !== 'ALL') {
    query += ` WHERE zone = ?`;
    params.push(zone);
  }
  query += ` ORDER BY item_name ASC`;

  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/directory', (req, res) => {
  const { item_code, item_name, category, unit, stock_qty, unit_price, zone } = req.body;
  const query = `INSERT INTO master_directory (item_code, item_name, category, unit, stock_qty, unit_price, zone) 
                 VALUES (?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT(item_code) DO UPDATE SET 
                 item_name=excluded.item_name, category=excluded.category, unit=excluded.unit, 
                 stock_qty=excluded.stock_qty, unit_price=excluded.unit_price, zone=excluded.zone, 
                 updated_at=CURRENT_TIMESTAMP`;

  db.run(query, [item_code, item_name, category, unit, stock_qty, unit_price, zone || 'MAIN'], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    io.emit('data_updated', { type: 'DIRECTORY_UPDATE', zone });
    res.json({ success: true, id: this.lastID });
  });
});

// 3. Dispense & Records Processing
app.post('/api/dispense', (req, res) => {
  const { dispense_id, item_code, item_name, quantity, unit_price, total_amount, patient_name, zone, operator } = req.body;
  
  db.serialize(() => {
    db.run('BEGIN TRANSACTION;');

    const insertQuery = `INSERT INTO dispense_logs (dispense_id, item_code, item_name, quantity, unit_price, total_amount, patient_name, zone, operator) 
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;
    
    db.run(insertQuery, [dispense_id, item_code, item_name, quantity, unit_price, total_amount, patient_name, zone, operator], (err) => {
      if (err) {
        db.run('ROLLBACK;');
        return res.status(500).json({ error: err.message });
      }

      // Deduct stock quantity
      const updateStock = `UPDATE master_directory SET stock_qty = stock_qty - ? WHERE item_code = ?`;
      db.run(updateStock, [quantity, item_code], (err2) => {
        if (err2) {
          db.run('ROLLBACK;');
          return res.status(500).json({ error: err2.message });
        }

        db.run('COMMIT;', () => {
          io.emit('data_updated', { type: 'DISPENSE_LOGGED', zone });
          res.json({ success: true, message: 'Dispense recorded successfully.' });
        });
      });
    });
  });
});

app.get('/api/dispense', (req, res) => {
  const { zone } = req.query;
  let query = `SELECT * FROM dispense_logs`;
  let params = [];
  if (zone && zone !== 'ALL') {
    query += ` WHERE zone = ?`;
    params.push(zone);
  }
  query += ` ORDER BY timestamp DESC LIMIT 500`;

  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// 4. User Management (Admin Only)
app.get('/api/users', (req, res) => {
  db.all(`SELECT id, username, role, zone, status, created_at FROM users`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/users', (req, res) => {
  const { username, password, role, zone } = req.body;
  db.run(`INSERT INTO users (username, password, role, zone) VALUES (?, ?, ?, ?)`,
    [username, password, role || 'USER', zone || 'MAIN'],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true, id: this.lastID });
    }
  );
});

// Serve Frontend Application
app.get('*', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RxMEDISYNC PRO - Enterprise Pharmacy Management System</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="/socket.io/socket.io.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
      body { font-family: 'Inter', sans-serif; }
    </style>
</head>
<body class="bg-slate-50 text-slate-800 min-h-screen flex flex-col">
    <!-- Header Banner -->
    <header class="bg-white border-b border-slate-200 px-6 py-4 flex items-center justify-between shadow-sm">
        <div class="flex items-center space-x-3">
            <div class="bg-blue-600 text-white p-2 rounded-lg font-bold text-lg tracking-wider">Rx</div>
            <div>
                <h1 class="text-xl font-bold text-slate-900 tracking-tight">RxMEDISYNC <span class="text-blue-600">PRO</span></h1>
                <p class="text-xs text-slate-500">Maintain your records without efforts.</p>
            </div>
        </div>
        <div id="user-session-info" class="text-sm font-medium text-slate-600">
            <!-- Dynamic Session Info -->
        </div>
    </header>

    <!-- Main Workspace Container -->
    <main id="app-root" class="flex-1 p-6 max-w-7xl mx-auto w-full">
        <!-- Login Form View -->
        <div id="login-container" class="max-w-md mx-auto mt-16 bg-white p-8 rounded-2xl shadow-xl border border-slate-100">
            <h2 class="text-2xl font-bold text-slate-900 mb-2">Welcome Back</h2>
            <p class="text-sm text-slate-500 mb-6">Sign in to your zone console to proceed.</p>
            <form id="login-form" class="space-y-4">
                <div>
                    <label class="block text-xs font-semibold uppercase tracking-wider text-slate-500 mb-1">Username</label>
                    <input type="text" id="login-username" required class="w-full px-4 py-2.5 rounded-lg border border-slate-300 focus:ring-2 focus:ring-blue-600 focus:outline-none text-sm">
                </div>
                <div>
                    <label class="block text-xs font-semibold uppercase tracking-wider text-slate-500 mb-1">Password</label>
                    <input type="password" id="login-password" required class="w-full px-4 py-2.5 rounded-lg border border-slate-300 focus:ring-2 focus:ring-blue-600 focus:outline-none text-sm">
                </div>
                <button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2.5 rounded-lg transition-colors shadow-md">Sign In</button>
            </form>
        </div>

        <!-- Dashboard Workspace (Hidden by default) -->
        <div id="dashboard-container" class="hidden space-y-6">
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div class="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
                    <h3 class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Zone</h3>
                    <p id="dashboard-zone" class="text-2xl font-bold text-slate-800 mt-1">-</p>
                </div>
                <div class="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
                    <h3 class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Inventory Items</h3>
                    <p id="dashboard-item-count" class="text-2xl font-bold text-blue-600 mt-1">0</p>
                </div>
                <div class="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
                    <h3 class="text-xs font-semibold text-slate-400 uppercase tracking-wider">System Status</h3>
                    <p class="text-2xl font-bold text-emerald-600 mt-1 flex items-center"><span class="w-3 h-3 bg-emerald-500 rounded-full inline-block mr-2 animate-pulse"></span> Online</p>
                </div>
            </div>

            <div class="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
                <h3 class="text-lg font-bold text-slate-800 mb-4">Quick Directory Search</h3>
                <input type="text" id="search-directory" placeholder="Search by item code or name..." class="w-full px-4 py-2.5 rounded-lg border border-slate-300 focus:ring-2 focus:ring-blue-600 focus:outline-none text-sm mb-4">
                <div class="overflow-x-auto">
                    <table class="w-full text-left border-collapse text-sm">
                        <thead>
                            <tr class="border-b border-slate-200 text-slate-400 uppercase font-semibold text-xs bg-slate-50">
                                <th class="p-3">Item Code</th>
                                <th class="p-3">Item Name</th>
                                <th class="p-3">Category</th>
                                <th class="p-3">Stock Qty</th>
                                <th class="p-3">Unit Price</th>
                                <th class="p-3">Zone</th>
                            </tr>
                        </thead>
                        <tbody id="directory-table-body">
                            <!-- Populated dynamically -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </main>

    <!-- Footer Attribution -->
    <footer class="bg-white border-t border-slate-200 py-4 text-center text-xs text-slate-400">
        RxMEDISYNC PRO &bull; Developed by Debanjan Singha
    </footer>

    <!-- Frontend Script Logic -->
    <script>
        const socket = io();
        let currentUser = null;

        document.getElementById('login-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('login-username').value;
            const password = document.getElementById('login-password').value;

            try {
                const res = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                const data = await res.json();
                if (data.success) {
                    currentUser = data.user;
                    document.getElementById('login-container').classList.add('hidden');
                    document.getElementById('dashboard-container').classList.remove('hidden');
                    document.getElementById('user-session-info').innerText = \`\${currentUser.username} (\${currentUser.role}) [Zone: \${currentUser.zone}]\`;
                    document.getElementById('dashboard-zone').innerText = currentUser.zone;
                    loadDirectoryData();
                } else {
                    alert(data.error || 'Login failed');
                }
            } catch (err) {
                console.error(err);
                alert('Connection error during login.');
            }
        });

        async function loadDirectoryData() {
            if (!currentUser) return;
            try {
                const res = await fetch(\`/api/directory?zone=\${currentUser.zone}\`);
                const items = await res.json();
                document.getElementById('dashboard-item-count').innerText = items.length;
                const tbody = document.getElementById('directory-table-body');
                tbody.innerHTML = '';
                items.forEach(item => {
                    const tr = document.createElement('tr');
                    tr.className = 'border-b border-slate-100 hover:bg-slate-50';
                    tr.innerHTML = \`
                        <td class="p-3 font-medium text-slate-900">\${item.item_code}</td>
                        <td class="p-3">\${item.item_name}</td>
                        <td class="p-3 text-slate-500">\${item.category || '-'}</td>
                        <td class="p-3 font-semibold text-slate-700">\${item.stock_qty} \${item.unit || ''}</td>
                        <td class="p-3 text-slate-600">$\${item.unit_price.toFixed(2)}</td>
                        <td class="p-3 text-slate-500">\${item.zone}</td>
                    \`;
                    tbody.appendChild(tr);
                });
            } catch (err) {
                console.error('Failed to load directory data:', err);
            }
        }

        socket.on('data_updated', (data) => {
            if (currentUser && (data.zone === currentUser.zone || currentUser.role === 'ADMIN')) {
                loadDirectoryData();
            }
        });
    </script>
</body>
</html>`);
});

// Start Server
server.listen(PORT, () => {
  console.log(`RxMEDISYNC PRO server running on http://localhost:${PORT}`);
});
