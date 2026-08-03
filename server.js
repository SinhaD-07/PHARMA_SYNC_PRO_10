const express = require('express');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// In-memory data store for persistence or state mirroring if needed
let serverMasterList = [];
let serverDailyLog = {};
let serverHistory = [];

// API Endpoints for sync / data storage if required by the app
app.get('/api/data', (req, res) => {
    res.json({
        master: serverMasterList,
        daily: serverDailyLog,
        history: serverHistory
    });
});

app.post('/api/data', (req, res) => {
    const { master, daily, history } = req.body;
    if (master) serverMasterList = master;
    if (daily) serverDailyLog = daily;
    if (history) serverHistory = history;
    res.json({ success: true });
});

// Serve User Interface (PHARMA-SYNC PRO | SMART FOCUS)
app.get('/', (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHARMA-SYNC PRO | SMART FOCUS</title>
    <meta name="author" content="Debanjan Singha">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.23/jspdf.plugin.autotable.min.js"></script>
    <style>
        :root {
            --bg: #f4f7fa;
            --accent: #4361ee;
            --success: #2ec4b6;
            --danger: #e71d36;
            --warning: #ff9f1c;
            --sidebar: #1b263b;
            --card-bg: #ffffff;
            --text-main: #2b2d42;
            --text-muted: #8d99ae;
        }

        body { font-family: 'Inter', sans-serif; background-color: var(--bg); color: var(--text-main); margin: 0; padding: 20px; }
        .container { max-width: 1400px; margin: auto; }

        .app-grid { display: grid; grid-template-columns: 300px 1fr 350px; gap: 20px; align-items: start; }
        @media (max-width: 1100px) { .app-grid { grid-template-columns: 1fr 1fr; } }
        @media (max-width: 768px) { .app-grid { grid-template-columns: 1fr; } }

        .header-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; background: white; padding: 15px 25px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }
        .panel { background: var(--card-bg); padding: 20px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.02); border: 1px solid #edf2f7; margin-bottom: 20px; position: relative; }
        .panel h2 { font-size: 15px; margin-top: 0; margin-bottom: 15px; color: var(--sidebar); border-bottom: 1px solid #f1f5f9; padding-bottom: 10px; text-transform: uppercase; letter-spacing: 0.5px; }

        input { width: 100%; padding: 10px 12px; border: 1px solid #d1d9e6; border-radius: 8px; font-size: 14px; box-sizing: border-box; margin-bottom: 10px; background: #f8fafc; }
        .primary-btn { background: var(--accent); color: white; padding: 10px; border: none; border-radius: 8px; cursor: pointer; font-weight: 700; width: 100%; transition: 0.2s; font-size: 13px; }
        .primary-btn:hover { filter: brightness(1.1); }

        .qty-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 6px; margin-bottom: 10px; }
        .qty-pill { background: #edf2f7; border: 1px solid #cbd5e0; padding: 6px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: bold; }
        .qty-pill:hover { background: var(--accent); color: white; }

        .table-wrap { max-height: 450px; overflow-y: auto; border: 1px solid #f1f5f9; border-radius: 6px; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th { background: #f8fafc; padding: 10px; text-align: left; color: var(--text-muted); position: sticky; top: 0; z-index: 10; }
        td { padding: 10px; border-bottom: 1px solid #f8fafc; }

        .badge { background: #e0e7ff; color: var(--accent); padding: 2px 8px; border-radius: 4px; font-weight: bold; }
        .action-link { cursor: pointer; font-size: 11px; font-weight: bold; text-decoration: underline; background: none; border: none; padding: 0 4px; }
        
        #importModal { position: fixed; inset: 0; background: rgba(0,0,0,0.5); display: none; place-items: center; z-index: 1000; backdrop-filter: blur(2px); }
        .modal-box { background: white; padding: 30px; border-radius: 15px; width: 350px; text-align: center; }

        .panel-credit { 
            margin-top: 20px;
            padding-top: 15px;
            border-top: 1px dashed #e2e8f0;
            font-size: 11px;
            color: var(--text-muted);
            text-align: center;
            line-height: 1.4;
        }
        .panel-credit b { color: var(--sidebar); }
    </style>
</head>
<body>

<div id="importModal">
    <div class="modal-box">
        <h3 style="margin-top:0">Importing Data</h3>
        <button class="primary-btn" style="background:var(--success); margin-bottom:8px" onclick="processImport('merge')">➕ MERGE TOTALS</button>
        <button class="primary-btn" style="background:var(--danger); margin-bottom:8px" onclick="processImport('replace')">🔄 RESET & REPLACE TOTALS</button>
        <button class="primary-btn" style="background:#64748b" onclick="closeModal()">CANCEL</button>
    </div>
</div>

<div class="container">
    <div class="header-bar">
        <h1 style="margin:0; font-size:20px; color:var(--sidebar)">PHARMA<span style="color:var(--accent)">SYNC</span> PRO</h1>
        <div style="display:flex; gap:8px">
            <button id="rollbackBtn" style="background:var(--warning); color:white; border:none; padding:8px 12px; border-radius:6px; cursor:pointer; font-weight:bold; display:none" onclick="undoImport()">↩ UNDO (<span id="rollbackCount">0</span>)</button>
            <button onclick="exportBackup()" style="background:#6366f1; color:white; border:none; padding:8px 12px; border-radius:6px; cursor:pointer; font-weight:bold">💾 BACKUP</button>
            <button onclick="document.getElementById('fileInput').click()" style="background:var(--sidebar); color:white; border:none; padding:8px 12px; border-radius:6px; cursor:pointer; font-weight:bold">📂 IMPORT</button>
            <input type="file" id="fileInput" style="display:none" onchange="handleFileSelect(event)" accept=".json">
        </div>
    </div>

    <div class="app-grid">
        <div class="panel">
            <h2>📦 Master Directory</h2>
            <input type="text" id="newDrugName" placeholder="New drug name..." onkeydown="if(event.key==='Enter') registerDrug()">
            <button class="primary-btn" onclick="registerDrug()">REGISTER DRUG</button>
            <input type="text" style="margin-top:20px" onkeyup="filterTable('masterBody', this.value)" placeholder="Search directory...">
            <div class="table-wrap"><table><tbody id="masterBody"></tbody></table></div>
            
            <div class="panel-credit">
                © 2026 <b>Debanjan Singha</b><br>
                System Architect & Lead Developer
            </div>
        </div>

        <div class="panel">
            <h2>🛒 Dispense Console</h2>
            <div style="display: grid; grid-template-columns: 1fr 120px; gap: 10px;">
                <input type="text" id="searchDrug" list="drugList" placeholder="Select Drug..." onkeydown="if(event.key==='Enter') document.getElementById('dispenseAmount').focus()">
                <input type="number" id="dispenseAmount" placeholder="Qty" onkeydown="if(event.key==='Enter') dispenseDrug()">
            </div>
            <datalist id="drugList"></datalist>
            <div class="qty-grid">
                <button class="qty-pill" onclick="setQty(1)">1</button>
                <button class="qty-pill" onclick="setQty(5)">5</button>
                <button class="qty-pill" onclick="setQty(10)">10</button>
                <button class="qty-pill" onclick="setQty(15)">15</button>
                <button class="qty-pill" onclick="setQty(20)">20</button>
                <button class="qty-pill" onclick="setQty(30)">30</button>
                <button class="qty-pill" onclick="setQty(60)">60</button>
                <button class="qty-pill" onclick="setQty(120)">120</button>
            </div>
            <button class="primary-btn" style="background:var(--success); height: 45px; font-size:16px" id="recordBtn" onclick="dispenseDrug()">RECORD ENTRY</button>

            <h2 style="margin-top:25px">📊 Today's Cumulative Totals</h2>
            <input type="text" onkeyup="filterTable('dailyBody', this.value)" placeholder="Filter totals...">
            <div class="table-wrap" style="max-height: 400px;">
                <table><thead><tr><th>Drug Name</th><th>Total</th></tr></thead><tbody id="dailyBody"></tbody></table>
            </div>
        </div>

        <div class="panel">
            <h2>🕒 Recent History</h2>
            <div class="table-wrap" style="max-height: 300px;"><table><tbody id="historyBody"></tbody></table></div>
            <button class="primary-btn" style="background:#94a3b8; margin-top:10px; padding:6px; font-size:11px" onclick="clearHistoryOnly()">CLEAR LOG</button>

            <h2 style="margin-top:25px">📄 Report & Maintenance</h2>
            <input type="text" id="pdfRemarks" placeholder="Enter remarks (Mandatory)...">
            <button class="primary-btn" style="background:var(--danger)" onclick="generateReport()">GENERATE PDF</button>
            <button class="primary-btn" style="background:#64748b; margin-top:8px" onclick="resetDailyDataOnly()">RESET TOTALS & HISTORY</button>
        </div>
    </div>
</div>

<script>
    let masterList = JSON.parse(localStorage.getItem('pharmacyMasterList')) || [];
    let dailyLog = JSON.parse(localStorage.getItem('pharmacyDailyLog')) || {};
    let transactionHistory = JSON.parse(localStorage.getItem('pharmacyHistory')) || [];
    let rollbackStack = JSON.parse(localStorage.getItem('pharmacyRollbackStack')) || [];
    let pendingImportData = null;

    function setQty(v) { 
        document.getElementById('dispenseAmount').value = v; 
        document.getElementById('recordBtn').focus(); 
    }

    function takeSnapshot() {
        rollbackStack.unshift({ master: [...masterList], daily: {...dailyLog}, history: [...transactionHistory] });
        if (rollbackStack.length > 3) rollbackStack.pop();
        localStorage.setItem('pharmacyRollbackStack', JSON.stringify(rollbackStack));
    }

    function checkRollback() {
        const btn = document.getElementById('rollbackBtn');
        btn.style.display = rollbackStack.length > 0 ? 'block' : 'none';
        document.getElementById('rollbackCount').innerText = rollbackStack.length;
    }

    function undoImport() {
        if (rollbackStack.length > 0 && confirm("Undo last action?")) {
            const state = rollbackStack.shift();
            masterList = state.master; dailyLog = state.daily; transactionHistory = state.history;
            saveData(); updateUI();
        }
    }

    function updateUI() {
        renderTable('masterBody', masterList.sort(), (item) => \`
            <td>\${item}</td>
            <td style="text-align:right">
                <button class="action-link" style="color:var(--warning)" onclick="editDrug('\${item}')">Edit</button>
                <button class="action-link" style="color:var(--danger)" onclick="removeDrug('\${item}')">Del</button>
            </td>
        \`);
        renderTable('dailyBody', Object.keys(dailyLog).sort(), (k) => \`<td>\${k}</td><td><span class="badge">\${dailyLog[k]}</span></td>\`);
        renderTable('historyBody', transactionHistory.slice(0, 50), (i) => \`
            <td><span style="color:gray; font-size:10px">\${i.time}</span><br>\${i.name} (<b>\${i.qty}</b>)</td>
            <td style="text-align:right">
                <button class="action-link" style="color:var(--warning)" onclick="editHistoryQty(\${i.id})">Edit</button>
                <button class="action-link" style="color:var(--danger)" onclick="undoTransaction(\${i.id})">Undo</button>
            </td>
        \`);
        document.getElementById('drugList').innerHTML = masterList.map(m => \`<option value="\${m}">\`).join('');
        checkRollback();
    }

    function renderTable(id, data, templateFn) { document.getElementById(id).innerHTML = data.map(item => \`<tr>\${templateFn(item)}</tr>\`).join(''); }

    function registerDrug() {
        const i = document.getElementById('newDrugName'); const n = i.value.trim().toUpperCase();
        if (n && !masterList.includes(n)) { masterList.push(n); saveData(); i.value = ''; updateUI(); }
    }

    function dispenseDrug() {
        const nI = document.getElementById('searchDrug'), aI = document.getElementById('dispenseAmount');
        const n = nI.value.trim().toUpperCase(), a = parseInt(aI.value);
        if (!masterList.includes(n) || isNaN(a) || a <= 0) return;
        dailyLog[n] = (dailyLog[n] || 0) + a;
        transactionHistory.unshift({ id: Date.now(), time: new Date().toLocaleTimeString(), name: n, qty: a });
        saveData(); nI.value = ''; aI.value = ''; updateUI(); nI.focus(); 
    }

    document.getElementById('searchDrug').addEventListener('input', function(e) {
        if (masterList.includes(this.value.toUpperCase())) document.getElementById('dispenseAmount').focus();
    });

    function handleFileSelect(e) {
        const r = new FileReader();
        r.onload = (ev) => { 
            try {
                pendingImportData = JSON.parse(ev.target.result); 
                document.getElementById('importModal').style.display = 'grid'; 
            } catch(err) { alert("Invalid File Format"); }
        };
        r.readAsText(e.target.files[0]);
    }

    function processImport(mode) {
        takeSnapshot();
        if (pendingImportData.master) masterList = [...new Set([...masterList, ...pendingImportData.master])];
        if (mode === 'replace') {
            dailyLog = pendingImportData.daily || {};
            transactionHistory = pendingImportData.history || [];
        } else {
            const inc = pendingImportData.daily || {};
            for (let d in inc) dailyLog[d] = (dailyLog[d] || 0) + inc[d];
            transactionHistory = [...transactionHistory, ...(pendingImportData.history || [])].sort((a,b)=>b.id-a.id).slice(0, 1000);
        }
        saveData(); updateUI(); closeModal();
    }

    function closeModal() { document.getElementById('importModal').style.display = 'none'; document.getElementById('fileInput').value = ""; }

    function resetDailyDataOnly() {
        if(confirm("Clear Today's Totals and History?")) {
            takeSnapshot(); dailyLog = {}; transactionHistory = []; saveData(); updateUI();
        }
    }

    function editDrug(old) {
        const n = prompt("Rename drug:", old);
        if (n && n.toUpperCase() !== old) {
            const newN = n.trim().toUpperCase();
            const idx = masterList.indexOf(old);
            masterList[idx] = newN;
            if (dailyLog[old]) { dailyLog[newN] = (dailyLog[newN] || 0) + dailyLog[old]; delete dailyLog[old]; }
            transactionHistory.forEach(i => { if (i.name === old) i.name = newN; });
            saveData(); updateUI();
        }
    }

    function removeDrug(n) { if(confirm("Delete drug?")) { masterList = masterList.filter(i=>i!==n); saveData(); updateUI(); } }
    function clearHistoryOnly() { if(confirm("Clear log?")) { transactionHistory = []; saveData(); updateUI(); } }
    
    function generateReport() {
        const r = document.getElementById('pdfRemarks').value.trim();
        if (!r) return alert("Remarks Required");
        const { jsPDF } = window.jspdf; const doc = new jsPDF();
        
        doc.text("PHARMA-SYNC DAILY REPORT", 14, 20);
        doc.setFontSize(10); 
        doc.text(\`Date: \${new Date().toLocaleString()} | Remarks: \${r}\`, 14, 28);
        
        doc.autoTable({ 
            startY: 35, 
            head: [['Drug Name', 'Total']], 
            body: Object.keys(dailyLog).sort().map(k => [k, dailyLog[k]]),
            didDrawPage: function (data) {
                if (doc.internal.getNumberOfPages() === 1) {
                    doc.setFontSize(8);
                    doc.text("System Architect: Debanjan Singha", 14, doc.internal.pageSize.height - 10);
                }
            }
        });
        
        doc.save(\`PharmaReport_\${Date.now()}.pdf\`);
        exportBackup();
    }

    function editHistoryQty(id) {
        const idx = transactionHistory.findIndex(i => i.id === id);
        if (idx === -1) return;
        const nQ = prompt("Correct quantity:", transactionHistory[idx].qty);
        const qInt = parseInt(nQ);
        if (!isNaN(qInt) && qInt > 0) {
            dailyLog[transactionHistory[idx].name] += (qInt - transactionHistory[idx].qty);
            transactionHistory[idx].qty = qInt;
            saveData(); updateUI();
        }
    }

    function undoTransaction(id) {
        const idx = transactionHistory.findIndex(i => i.id === id);
        if (idx > -1) {
            const item = transactionHistory[idx];
            dailyLog[item.name] -= item.qty;
            if (dailyLog[item.name] <= 0) delete dailyLog[item.name];
            transactionHistory.splice(idx, 1); saveData(); updateUI();
        }
    }

    function filterTable(id, val) {
        const rows = document.getElementById(id).rows; const s = val.toUpperCase();
        for (let r of rows) r.style.display = r.innerText.toUpperCase().includes(s) ? "" : "none";
    }

    function saveData() {
        localStorage.setItem('pharmacyMasterList', JSON.stringify(masterList));
        localStorage.setItem('pharmacyDailyLog', JSON.stringify(dailyLog));
        localStorage.setItem('pharmacyHistory', JSON.stringify(transactionHistory));
    }

    function exportBackup() {
        const blob = new Blob([JSON.stringify({master: masterList, daily: dailyLog, history: transactionHistory})], {type: 'application/json'});
        const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = \`PharmaBackup_\${Date.now()}.json\`; a.click();
    }
    updateUI();
</script>
</body>
</html>`);
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
