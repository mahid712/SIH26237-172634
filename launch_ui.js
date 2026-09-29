// launch_ui.js: Completely local, offline static server to preview the desktop UI
const http = require('http');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

const PORT = 3456;
const UI_DIR = path.join(__dirname, 'src-ui');

const MIME_TYPES = {
    '.html': 'text/html',
    '.css': 'text/css',
    '.js': 'text/javascript',
    '.json': 'application/json',
    '.png': 'image/png',
    '.jpg': 'image/jpeg'
};

const server = http.createServer((req, res) => {
    let reqPath = req.url === '/' ? '/index.html' : req.url;
    let filePath = path.join(UI_DIR, reqPath);
    let ext = path.extname(filePath);
    let contentType = MIME_TYPES[ext] || 'application/octet-stream';

    fs.readFile(filePath, (err, content) => {
        if (err) {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('404 Not Found');
        } else {
            res.writeHead(200, { 'Content-Type': contentType });
            res.end(content);
        }
    });
});

server.listen(PORT, '127.0.0.1', () => {
    console.log(`\n======================================================`);
    console.log(`  PQC OFFLINE SECURE BROADCAST - LOCAL DESKTOP UI`);
    console.log(`======================================================`);
    console.log(`  Status: Running locally on 127.0.0.1:${PORT}`);
    console.log(`  Air-gapped: ZERO external internet access needed`);
    console.log(`  Opening browser automatically...`);
    console.log(`======================================================\n`);

    // Open default browser on Windows
    exec(`start http://127.0.0.1:${PORT}`);
});
