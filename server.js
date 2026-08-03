const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware for parsing JSON and URL-encoded data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files (CSS, client-side JS, images) from a 'public' folder if it exists
app.use(express.static(path.join(__dirname, 'public')));

// In-memory data store fallback (or connect your database/file sync here)
const DATA_FILE = path.join(__dirname, 'data', 'master-directory.json');

// Ensure data directory exists
if (!fs.existsSync(path.dirname(DATA_FILE))) {
    fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
}

// Helper to read data safely
function readData() {
    try {
        if (!fs.existsSync(DATA_FILE)) return [];
        const fileData = fs.readFileSync(DATA_FILE, 'utf8');
        return JSON.parse(fileData);
    } catch (err) {
        console.error('Error reading data file:', err);
        return [];
    }
}

// Helper to write data safely
function writeData(data) {
    try {
        fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
        return true;
    } catch (err) {
        console.error('Error writing data file:', err);
        return false;
    }
}

// --- API Endpoints ---

// Get all directory entries
app.get('/api/directory', (req, res) => {
    const data = readData();
    res.json({ success: true, data });
});

// Add a new entry (optimized for fast data entry)
app.post('/api/directory', (req, res) => {
    const data = readData();
    const newEntry = {
        id: Date.now().toString(),
        ...req.body,
        createdAt: new Date().toISOString()
    };
    
    data.push(newEntry);
    
    if (writeData(data)) {
        res.status(201).json({ success: true, message: 'Entry added successfully', data: newEntry });
    } else {
        res.status(500).json({ success: false, message: 'Failed to save entry' });
    }
});

// Update an existing entry
app.put('/api/directory/:id', (req, res) => {
    const { id } = req.params;
    let data = readData();
    const index = data.findIndex(item => item.id === id);

    if (index === -1) {
        return res.status(404).json({ success: false, message: 'Entry not found' });
    }

    data[index] = { ...data[index], ...req.body, updatedAt: new Date().toISOString() };

    if (writeData(data)) {
        res.json({ success: true, message: 'Entry updated successfully', data: data[index] });
    } else {
        res.status(500).json({ success: false, message: 'Failed to update entry' });
    }
});

// Delete an entry
app.delete('/api/directory/:id', (req, res) => {
    const { id } = req.params;
    let data = readData();
    const filteredData = data.filter(item => item.id !== id);

    if (data.length === filteredData.length) {
        return res.status(404).json({ success: false, message: 'Entry not found' });
    }

    if (writeData(filteredData)) {
        res.json({ success: true, message: 'Entry deleted successfully' });
    } else {
        res.status(500).json({ success: false, message: 'Failed to delete entry' });
    }
});

// --- Main Application Route ---
app.get('*', (req, res) => {
    const indexPath = path.join(__dirname, 'public', 'index.html');
    if (fs.existsSync(indexPath)) {
        res.sendFile(indexPath);
    } else {
        // Fallback default UI response if index.html is missing
        res.send(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Master Directory</title>
                <style>
                    body { font-family: system-ui, -apple-system, sans-serif; background: #f8fafc; color: #1e293b; padding: 2rem; max-width: 800px; margin: 0 auto; }
                    h1 { color: #0f172a; }
                    .card { background: white; padding: 1.5rem; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-top: 1rem; }
                </style>
            </head>
            <body>
                <h1>Master Directory Application</h1>
                <div class="card">
                    <p>Server is up and running successfully!</p>
                    <p>Place your frontend files inside the <code>public</code> directory to load your custom interface.</p>
                </div>
            </body>
            </html>
        `);
    }
});

// Start Server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
