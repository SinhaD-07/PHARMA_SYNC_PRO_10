const express = require('express');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- IN-MEMORY DATABASE (Mock Data) ---
let users = [
    { id: 1, name: 'Alice Smith', email: 'alice@example.com', role: 'Admin', zone: 'Zone A', status: 'Active' },
    { id: 2, name: 'Bob Jones', email: 'bob@example.com', role: 'Operator', zone: 'Zone B', status: 'Active' },
    { id: 3, name: 'Charlie Brown', email: 'charlie@example.com', role: 'Viewer', zone: 'Unassigned', status: 'Inactive' }
];

let zones = ['Zone A', 'Zone B', 'Zone C', 'Unassigned'];

let activityLogs = [
    { id: 101, username: 'Alice Smith', action: 'LOGIN', timestamp: new Date(Date.now() - 3600000).toISOString() },
    { id: 102, username: 'Bob Jones', action: 'LOGOUT', timestamp: new Date(Date.now() - 1800000).toISOString() }
];

let auditLogs = [
    { id: 501, user: 'Alice Smith', action: 'UPDATE_CONFIG', details: 'Changed system timeout threshold', timestamp: new Date(Date.now() - 2500000).toISOString() },
    { id: 502, user: 'Bob Jones', action: 'DELETE_USER_RECORD', details: 'Archived legacy test accounts', timestamp: new Date(Date.now() - 1200000).toISOString() }
];

// --- API ROUTES ---

// 1. Get Dashboard State
apiRouter = express.Router();
apiRouter.get('/data', (req, res) => {
    res.json({ users, zones, activityLogs, auditLogs });
});

// 2. Zone Management: Update User Zone
apiRouter.post('/users/:id/zone', (req, res) => {
    const userId = parseInt(req.params.id);
    const { zone } = req.body;
    const user = users.find(u => u.id === userId);
    
    if (!user) {
        return res.status(404).json({ success: false, message: 'User not found' });
    }
    if (!zones.includes(zone)) {
        return res.status(400).json({ success: false, message: 'Invalid zone specified' });
    }

    user.zone = zone;
    
    // Log this administrative action to audit logs automatically
    auditLogs.unshift({
        id: Date.now(),
        user: 'System Admin',
        action: 'EDIT_ZONE',
        details: `Assigned user ${user.name} to ${zone}`,
        timestamp: new Date().toISOString()
    });

    res.json({ success: true, user, auditLogs });
});

// 3. Activity Tracker Deletion Route (Manual Delete)
apiRouter.delete('/activity/:id', (req, res) => {
    const logId = parseInt(req.params.id);
    const initialLength = activityLogs.length;
    activityLogs = activityLogs.filter(log => log.id !== logId);

    if (activityLogs.length === initialLength) {
        return res.status(404).json({ success: false, message: 'Activity log entry not found' });
    }

    res.json({ success: true, message: 'Activity log deleted successfully', activityLogs });
});

// Clear all activity tracker logs option
apiRouter.delete('/activity', (req, res) => {
    activityLogs = [];
    res.json({ success: true, message: 'All activity logs cleared', activityLogs });
});

// 4. Transaction Audit Logs Deletion Route (Manual Delete)
apiRouter.delete('/audit/:id', (req, res) => {
    const logId = parseInt(req.params.id);
    const initialLength = auditLogs.length;
    auditLogs = auditLogs.filter(log => log.id !== logId);

    if (auditLogs.length === initialLength) {
        return res.status(404).json({ success: false, message: 'Audit log entry not found' });
    }

    res.json({ success: true, message: 'Audit log deleted successfully', auditLogs });
});

// Clear all audit logs option
apiRouter.delete('/audit', (req, res) => {
    auditLogs = [];
    res.json({ success: true, message: 'All audit logs cleared', auditLogs });
});

app.use('/api', apiRouter);

// --- FRONTEND VIEW (HTML / CSS / JS SPA) ---
app.get('/', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Operations & Tracking Dashboard</title>
        <style>
            :root {
                --primary: #4f46e5;
                --primary-hover: #4338ca;
                --bg-main: #f9fafb;
                --surface: #ffffff;
                --text-main: #1f2937;
                --text-muted: #6b7280;
                --border: #e5e7eb;
                --danger: #ef4444;
                --danger-hover: #dc2626;
            }
            body {
                font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                background-color: var(--bg-main);
                color: var(--text-main);
                margin: 0;
                padding: 24px;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
            }
            header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 24px;
            }
            h1 { font-size: 1.5rem; font-weight: 700; margin: 0; }
            .card {
                background: var(--surface);
                border: 1px solid var(--border);
                border-radius: 8px;
                padding: 20px;
                margin-bottom: 24px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.05);
            }
            .card-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 16px;
            }
            h2 { font-size: 1.1rem; font-weight: 600; margin: 0; color: var(--text-main); }
            table {
                width: 100%;
                border-collapse: collapse;
                text-align: left;
                font-size: 0.875rem;
            }
            th, td {
                padding: 10px 12px;
                border-bottom: 1px solid var(--border);
            }
            th {
                background-color: #f3f4f6;
                color: var(--text-muted);
                font-weight: 600;
            }
            select, button {
                font-size: 0.875rem;
                padding: 6px 10px;
                border-radius: 4px;
                border: 1px solid var(--border);
            }
            button {
                cursor: pointer;
                background: var(--primary);
                color: white;
                border: none;
                font-weight: 500;
                transition: background 0.2s;
            }
            button:hover { background: var(--primary-hover); }
            button.btn-danger {
                background: var(--danger);
            }
            button.btn-danger:hover { background: var(--danger-hover); }
            .badge {
                padding: 2px 8px;
                border-radius: 12px;
                font-size: 0.75rem;
                font-weight: 500;
                background: #e0e7ff;
                color: #3730a3;
            }
            .actions-bar {
                display: flex;
                gap: 8px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>System Operations & Audit Dashboard</h1>
                <span class="badge" id="system-status">Live Server Connected</span>
            </header>

            <!-- User Management & Zones Grid -->
            <div class="card">
                <div class="card-header">
                    <h2>User Accounts & Zone Assignment</h2>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Current Zone</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="users-table-body">
                        <!-- Populated Dynamically -->
                    </tbody>
                </table>
            </div>

            <!-- Activity Tracker Grid -->
            <div class="card">
                <div class="card-header">
                    <h2>User Login / Logout Activity Tracker</h2>
                    <button class="btn-danger" onclick="clearAllLogs('activity')">Clear All Activity Logs</button>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Log ID</th>
                            <th>Username</th>
                            <th>Action Type</th>
                            <th>Timestamp</th>
                            <th>Manual Action</th>
                        </tr>
                    </thead>
                    <tbody id="activity-table-body">
                        <!-- Populated Dynamically -->
                    </tbody>
                </table>
            </div>

            <!-- Transaction Audit Logs Grid -->
            <div class="card">
                <div class="card-header">
                    <h2>Transaction Audit Logs</h2>
                    <button class="btn-danger" onclick="clearAllLogs('audit')">Clear All Audit Logs</button>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Log ID</th>
                            <th>User</th>
                            <th>Action</th>
                            <th>Details</th>
                            <th>Timestamp</th>
                            <th>Manual Action</th>
                        </tr>
                    </thead>
                    <tbody id="audit-table-body">
                        <!-- Populated Dynamically -->
                    </tbody>
                </table>
            </div>
        </div>

        <script>
            async function fetchDashboardData() {
                try {
                    const res = await fetch('/api/data');
                    const data = await res.json();
                    renderUI(data);
                } catch (err) {
                    console.error('Failed to load dashboard data', err);
                }
            }

            function renderUI(data) {
                // Render Users Table
                const userTbody = document.getElementById('users-table-body');
                userTbody.innerHTML = data.users.map(user => \`
                    <tr>
                        <td>\${user.name}</td>
                        <td>\${user.email}</td>
                        <td>\${user.role}</td>
                        <td><span class="badge">\${user.zone}</span></td>
                        <td>
                            <div class="actions-bar">
                                <select id="zone-select-\${user.id}">
                                    \${data.zones.map(z => \`<option value="\${z}" \${z === user.zone ? 'selected' : ''}>\${z}</option>\`).join('')}
                                </select>
                                <button onclick="updateUserZone(\${user.id})">Edit Zone</button>
                            </div>
                        </td>
                    ></tr>
                \`).join('');

                // Render Activity Tracker Table
                const activityTbody = document.getElementById('activity-table-body');
                if (data.activityLogs.length === 0) {
                    activityTbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #6b7280;">No activity logs found.</td></tr>';
                } else {
                    activityTbody.innerHTML = data.activityLogs.map(log => \`
                        <tr>
                            <td>\${log.id}</td>
                            <td>\${log.username}</td>
                            <td><b>\${log.action}</b></td>
                            <td>\${new Date(log.timestamp).toLocaleString()}</td>
                            <td>
                                <button class="btn-danger" onclick="deleteLog('activity', \${log.id})">Delete</button>
                            </td>
                        </tr>
                    \`).join('');
                }

                // Render Audit Logs Table
                const auditTbody = document.getElementById('audit-table-body');
                if (data.auditLogs.length === 0) {
                    auditTbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: #6b7280;">No audit logs found.</td></tr>';
                } else {
                    auditTbody.innerHTML = data.auditLogs.map(log => \`
                        <tr>
                            <td>\${log.id}</td>
                            <td>\${log.user}</td>
                            <td>\${log.action}</td>
                            <td>\${log.details}</td>
                            <td>\${new Date(log.timestamp).toLocaleString()}</td>
                            <td>
                                <button class="btn-danger" onclick="deleteLog('audit', \${log.id})">Delete</button>
                            </td>
                        </tr>
                    \`).join('');
                }
            }

            async function updateUserZone(userId) {
                const selectedZone = document.getElementById(\`zone-select-\${userId}\`).value;
                try {
                    const res = await fetch(\`/api/users/\${userId}/zone\`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ zone: selectedZone })
                    });
                    const result = await res.json();
                    if (result.success) {
                        fetchDashboardData();
                    } else {
                        alert('Error: ' + result.message);
                    }
                } catch (err) {
                    console.error('Network error updating zone', err);
                }
            }

            async function deleteLog(type, id) {
                if (!confirm('Are you sure you want to delete this log entry?')) return;
                try {
                    const res = await fetch(\`/api/\${type}/\${id}\`, { method: 'DELETE' });
                    const result = await res.json();
                    if (result.success) {
                        fetchDashboardData();
                    } else {
                        alert('Error: ' + result.message);
                    }
                } catch (err) {
                    console.error('Network error deleting log', err);
                }
            }

            async function clearAllLogs(type) {
                if (!confirm(\*Are you sure you want to wipe all \${type} logs?\*)) return;
                try {
                    const res = await fetch(\`/api/\${type}\`, { method: 'DELETE' });
                    const result = await res.json();
                    if (result.success) {
                        fetchDashboardData();
                    }
                } catch (err) {
                    console.error('Network error clearing logs', err);
                }
            }

            // Load on startup
            fetchDashboardData();
        </script>
    </body>
    </html>
    `);
});

// Start Server
app.listen(PORT, () => {
    console.log(`Server is running successfully on http://localhost:${PORT}`);
});
