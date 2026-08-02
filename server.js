/*******************************************************************************
 * RxMEDISYNC PRO - Enterprise Backend Server & Integrated SPA Frontend
 * 
 * Description: Express backend configured with Firebase Admin SDK, batch data 
 * operations, and a fully embedded responsive frontend console utilizing the 
 * official RxMEDISYNC PRO branding and visual identity.
 * 
 * Developed by: Debanjan Singha
 ******************************************************************************/

import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import admin from 'firebase-admin';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// Fix directory paths for ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 5000;

// -----------------------------------------------------------------------------
// 1. Firebase Admin Initialisation
// -----------------------------------------------------------------------------
if (!admin.apps.length) {
  try {
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
      }),
    });
    console.log('✅ Firebase Admin SDK initialized successfully.');
  } catch (error) {
    console.warn('⚠️ Firebase Admin failed to initialize. Make sure .env variables are set.', error.message);
  }
}

const db = admin.apps.length ? admin.firestore() : null;

// -----------------------------------------------------------------------------
// 2. Middleware Configuration
// -----------------------------------------------------------------------------
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '10mb' })); // Allows bulk data entry JSON uploads
app.use(express.urlencoded({ extended: true }));

// Serve static assets if public folder exists
app.use(express.static(path.join(__dirname, 'public')));

// Request logging middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} request to ${req.url}`);
  next();
});

// -----------------------------------------------------------------------------
// 3. API Routes (RxMedisync Pro Core Endpoints)
// -----------------------------------------------------------------------------

// Health Check / System Status
app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'online',
    app: 'RxMEDISYNC PRO Backend',
    timestamp: new Date().toISOString(),
  });
});

// GET: Fetch Master Records Directory
app.get('/api/records', async (req, res) => {
  try {
    if (!db) {
      // Fallback mock data if Firestore is unconfigured
      return res.status(200).json({ success: true, count: 0, data: [], message: 'Firestore not configured; running in mock mode.' });
    }
    const snapshot = await db.collection('records').orderBy('createdAt', 'desc').get();
    const records = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    
    return res.status(200).json({ success: true, count: records.length, data: records });
  } catch (error) {
    console.error('Error fetching records:', error);
    return res.status(500).json({ success: false, message: 'Failed to retrieve records.' });
  }
});

// POST: Add Single/Bulk Records ("Maintain records without efforts")
app.post('/api/records', async (req, res) => {
  try {
    const { items, executiveId } = req.body;

    if (!items || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ success: false, message: 'Invalid payload. Items array required.' });
    }

    if (!db) {
      return res.status(500).json({ success: false, message: 'Database client not initialized.' });
    }

    const batch = db.batch();
    const collectionRef = db.collection('records');

    items.forEach((item) => {
      const docRef = collectionRef.doc();
      batch.set(docRef, {
        ...item,
        createdByExecutive: executiveId || 'System Executive',
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    });

    await batch.commit();

    return res.status(201).json({
      success: true,
      message: `${items.length} record(s) processed and synchronized successfully.`,
    });
  } catch (error) {
    console.error('Error inserting records:', error);
    return res.status(500).json({ success: false, message: 'Server error while saving records.' });
  }
});

// DELETE: Remove Record by ID
app.delete('/api/records/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (!db) return res.status(500).json({ success: false, message: 'Database not initialized.' });
    
    await db.collection('records').doc(id).delete();
    return res.status(200).json({ success: true, message: `Record ${id} deleted successfully.` });
  } catch (error) {
    console.error('Error deleting record:', error);
    return res.status(500).json({ success: false, message: 'Failed to delete record.' });
  }
});

// -----------------------------------------------------------------------------
// 4. Frontend Fallback (Embedded SPA Console with Integrated Branding)
// -----------------------------------------------------------------------------
app.get('*', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RxMEDISYNC PRO - Enterprise Pharmacy Management System</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; }
    </style>
</head>
<body class="bg-slate-100 text-slate-800 min-h-screen flex flex-col justify-between">

    <!-- Header Section with Integrated Logo -->
    <header class="bg-white border-b border-slate-200 shadow-sm sticky top-0 z-50">
        <div class="max-w-7xl mx-auto px-6 py-4 flex flex-col md:flex-row items-center justify-between gap-4">
            
            <!-- Brand Identity Container matching official logo design -->
            <div class="flex items-center space-x-4">
                <!-- Graphical Medical Cross & Care Symbol representation -->
                <div class="relative flex items-center justify-center w-12 h-12 bg-blue-50 border border-blue-200 rounded-xl shadow-inner">
                    <svg class="w-8 h-8 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path>
                    </svg>
                </div>
                <div>
                    <div class="flex items-center space-x-2">
                        <span class="text-2xl font-extrabold tracking-tight text-blue-600">Rx</span>
                        <span class="text-2xl font-extrabold tracking-tight text-slate-900">MEDISYNC</span>
                        <span class="px-2 py-0.5 text-xs font-bold text-white bg-slate-900 rounded-md shadow-sm">PRO</span>
                    </div>
                    <p class="text-xs font-medium text-slate-500 tracking-wide">Maintain your records without efforts.</p>
                </div>
            </div>

            <!-- Session Quick Stats -->
            <div class="flex items-center space-x-4">
                <div class="bg-slate-50 border border-slate-200 px-4 py-2 rounded-xl text-right">
                    <p class="text-[10px] uppercase font-bold tracking-wider text-slate-400">System Status</p>
                    <p class="text-xs font-bold text-emerald-600 flex items-center justify-end">
                        <span class="w-2 h-2 bg-emerald-500 rounded-full inline-block mr-1.5 animate-pulse"></span> Fully Operational
                    </p>
                </div>
            </div>
        </div>
    </header>

    <!-- Main Workspace -->
    <main class="max-w-7xl mx-auto px-6 py-8 w-full flex-1 space-y-6">
        
        <!-- Action Control Panel -->
        <div class="bg-white rounded-2xl shadow-sm border border-slate-200 p-6 flex flex-col md:flex-row justify-between items-center gap-4">
            <div>
                <h2 class="text-xl font-bold text-slate-900">Master Records Console</h2>
                <p class="text-sm text-slate-500">Manage patient records, prescriptions, and inventory effortlessly.</p>
            </div>
            <div class="flex items-center space-x-3 w-full md:w-auto">
                <button onclick="fetchRecords()" class="flex-1 md:flex-none px-5 py-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 font-semibold rounded-xl text-sm transition-colors">
                    🔄 Refresh Data
                </button>
                <button onclick="openAddModal()" class="flex-1 md:flex-none px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-xl text-sm shadow-md transition-colors">
                    + Add New Record
                </button>
            </div>
        </div>

        <!-- Records Table Section -->
        <div class="bg-white rounded-2xl shadow-sm border border-slate-200 overflow-hidden">
            <div class="overflow-x-auto">
                <table class="w-full text-left border-collapse">
                    <thead>
                        <tr class="bg-slate-50 border-b border-slate-200 text-slate-400 text-xs uppercase font-semibold tracking-wider">
                            <th class="p-4">Record ID / Item</th>
                            <th class="p-4">Category</th>
                            <th class="p-4">Quantity / Stock</th>
                            <th class="p-4">Executive</th>
                            <th class="p-4">Timestamp</th>
                            <th class="p-4 text-right">Actions</th>
                        </tr>
                    </thead>
                    <tbody id="records-table-body" class="divide-y divide-slate-100 text-sm">
                        <tr>
                            <td colspan="6" class="p-8 text-center text-slate-400">Loading master records directory...</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </main>

    <!-- Modal for Adding Record -->
    <div id="record-modal" class="fixed inset-0 bg-slate-900/50 backdrop-blur-sm hidden items-center justify-center z-50 p-4">
        <div class="bg-white rounded-2xl max-w-lg w-full p-6 shadow-2xl border border-slate-100 space-y-4">
            <div class="flex justify-between items-center pb-3 border-b border-slate-100">
                <h3 class="text-lg font-bold text-slate-900">Add New Master Record</h3>
                <button onclick="closeAddModal()" class="text-slate-400 hover:text-slate-600 font-bold text-xl">&times;</button>
            </div>
            <form id="record-form" onsubmit="submitRecord(event)" class="space-y-4">
                <div>
                    <label class="block text-xs font-semibold uppercase tracking-wider text-slate-500 mb-1">Item Name / Title</label>
                    <input type="text" id="item-name" required class="w-full px-4 py-2.5 rounded-xl border border-slate-300 focus:ring-2 focus:ring-blue-600 focus:outline-none text-sm">
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <label class="block text-xs font-semibold uppercase tracking-wider text-slate-500 mb-1">Category</label>
                        <input type="text" id="item-category" placeholder="e.g., Pharmaceuticals" required class="w-full px-4 py-2.5 rounded-xl border border-slate-300 focus:ring-2 focus:ring-blue-600 focus:outline-none text-sm">
                    </div>
                    <div>
                        <label class="block text-xs font-semibold uppercase tracking-wider text-slate-500 mb-1">Quantity</label>
                        <input type="number" id="item-qty" placeholder="100" required class="w-full px-4 py-2.5 rounded-xl border border-slate-300 focus:ring-2 focus:ring-blue-600 focus:outline-none text-sm">
                    </div>
                </div>
                <div>
                    <label class="block text-xs font-semibold uppercase tracking-wider text-slate-500 mb-1">Executive ID</label>
                    <input type="text" id="executive-id" value="System Executive" required class="w-full px-4 py-2.5 rounded-xl border border-slate-300 focus:ring-2 focus:ring-blue-600 focus:outline-none text-sm">
                </div>
                <div class="flex justify-end space-x-3 pt-3 border-t border-slate-100">
                    <button type="button" onclick="closeAddModal()" class="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 font-semibold rounded-xl text-sm">Cancel</button>
                    <button type="submit" class="px-5 py-2 bg-blue-600 hover:bg-blue-750 text-white font-semibold rounded-xl text-sm shadow-md">Save Record</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Footer Attribution -->
    <footer class="bg-white border-t border-slate-200 py-4 text-center text-xs text-slate-400">
        RxMEDISYNC PRO &bull; Developed by Debanjan Singha
    </footer>

    <!-- Client Script Logic -->
    <script>
        async function fetchRecords() {
            try {
                const res = await fetch('/api/records');
                const result = await res.json();
                const tbody = document.getElementById('records-table-body');
                
                if (!result.success || result.data.length === 0) {
                    tbody.innerHTML = \`<tr><td colspan="6" class="p-8 text-center text-slate-400">No records found in directory. Click "Add New Record" to start.</td></tr>\`;
                    return;
                }

                tbody.innerHTML = '';
                result.data.forEach(record => {
                    const tr = document.createElement('tr');
                    tr.className = 'hover:bg-slate-50/80 transition-colors';
                    tr.innerHTML = \`
                        <td class="p-4 font-semibold text-slate-900">\${record.itemName || record.name || 'Unnamed Item'}</td>
                        <td class="p-4 text-slate-600">\${record.category || 'General'}</td>
                        <td class="p-4 font-medium text-slate-700">\${record.quantity || record.qty || 0}</td>
                        <td class="p-4 text-slate-500 text-xs">\${record.createdByExecutive || 'System'}</td>
                        <td class="p-4 text-slate-400 text-xs">\${record.createdAt ? new Date(record.createdAt._seconds ? record.createdAt._seconds * 1000 : record.createdAt).toLocaleString() : 'Just now'}</td>
                        <td class="p-4 text-right">
                            <button onclick="deleteRecord('\${record.id}')" class="text-rose-500 hover:text-rose-700 font-medium text-xs px-2.5 py-1 bg-rose-50 rounded-lg">Delete</button>
                        </td>
                    \`;
                    tbody.appendChild(tr);
                });
            } catch (err) {
                console.error('Error loading records:', err);
            }
        }

        function openAddModal() {
            document.getElementById('record-modal').classList.remove('hidden');
            document.getElementById('record-modal').classList.add('flex');
        }

        function closeAddModal() {
            document.getElementById('record-modal').classList.remove('flex');
            document.getElementById('record-modal').classList.add('hidden');
        }

        async function submitRecord(e) {
            e.preventDefault();
            const newItem = {
                itemName: document.getElementById('item-name').value,
                category: document.getElementById('item-category').value,
                quantity: Number(document.getElementById('item-qty').value),
            };
            const executiveId = document.getElementById('executive-id').value;

            try {
                const res = await fetch('/api/records', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ items: [newItem], executiveId })
                });
                const data = await res.json();
                if (data.success) {
                    closeAddModal();
                    document.getElementById('record-form').reset();
                    fetchRecords();
                } else {
                    alert(data.message || 'Failed to save record.');
                }
            } catch (err) {
                console.error('Submission error:', err);
                alert('Server error while saving.');
            }
        }

        async function deleteRecord(id) {
            if (!confirm('Are you sure you want to delete this record?')) return;
            try {
                const res = await fetch(\`/api/records/\${id}\`, { method: 'DELETE' });
                const data = await res.json();
                if (data.success) {
                    fetchRecords();
                } else {
                    alert(data.message || 'Failed to delete record.');
                }
            } catch (err) {
                console.error('Deletion error:', err);
            }
        }

        // Initialize table data on load
        fetchRecords();
    </script>
</body>
</html>`);
});

// -----------------------------------------------------------------------------
// 5. Start Server
// -----------------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`
  🚀 RxMEDISYNC PRO Server is running!
  📡 Listening on: http://localhost:${PORT}
  📁 Serving integrated frontend console and Firebase endpoints
  `);
});
