const socket = io();

// Track attacker IPs
const attackers = new Map(); // { ip: { count, attacks: [] } }

// Initial Setup
document.addEventListener('DOMContentLoaded', () => {
    if (window.feather) feather.replace();
    if (window.feather) feather.replace();
    fetchStatus();

    // File upload handlers
    const httpFileInput = document.getElementById('file-input-http');
    if (httpFileInput) {
        httpFileInput.addEventListener('change', (e) => handleFileUpload(e, 'http'));
    }
    
    const ftpFileInput = document.getElementById('file-input-ftp');
    if (ftpFileInput) {
        ftpFileInput.addEventListener('change', (e) => handleFileUpload(e, 'ftp'));
    }
});

// Socket Events
socket.on('connect', () => {
    logSystem('Connected to Network Monitor System');
});

socket.on('disconnect', () => {
    logSystem('Connection Lost - System Offline', 'error');
});

socket.on('status_update', (data) => {
    updateServiceUI(data.service, data.running, data.port);
});

socket.on('stats_update', (data) => {
    updateStats(data);
});

socket.on('new_log', (data) => {
    logMessage(data.message);
});

socket.on('clear_logs', () => {
    const terminal = document.getElementById('log-terminal');
    terminal.innerHTML = '<div class="log-entry system">Logs cleared...</div>';
});

// UI Actions
async function toggleService(service) {
    const btn = document.getElementById(`btn-${service}`);
    const portInput = document.getElementById(`port-${service}`);
    const port = portInput ? portInput.value : null;

    // Check if already running (though UI should handle this by disabling start button)
    // Actually the Start button is always valid unless running.
    // Logic: If Stopped -> Start. If Running -> Stop (handled by Stop button).

    // Get uploaded file path if exists
    let htmlFile = null;
    if (service === 'http') {
        const fileLabel = document.getElementById('file-label-http');
        if (fileLabel && fileLabel.dataset.filepath) {
            htmlFile = fileLabel.dataset.filepath;
        }
    }

    try {
        btn.disabled = true;
        btn.innerText = "...";

        const response = await fetch(`/api/start/${service}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ port: port, html_file: htmlFile })
        });

        const data = await response.json();
        if (!response.ok) {
            logSystem(`Error starting ${service}: ${data.error}`, 'error');
            btn.innerText = "Start";
            btn.disabled = false;
        } else {
            logSystem(`Started ${service.toUpperCase()} on port ${data.port}`);
        }
    } catch (error) {
        logSystem(`Network Error: ${error}`, 'error');
        btn.innerText = "Start";
        btn.disabled = false;
    }
}

async function stopServiceReq(service) {
    const btn = document.querySelector(`#btn-${service}`).parentElement.querySelector('.btn-stop');

    try {
        btn.innerText = "...";
        btn.disabled = true;

        const response = await fetch(`/api/stop/${service}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });

        const data = await response.json();
        if (!response.ok) {
            logSystem(`Error stopping ${service}: ${data.error}`, 'error');
            btn.innerText = "Stop";
            btn.disabled = false;
        } else {
            logSystem(`Stopped ${service.toUpperCase()} service`);
        }
    } catch (error) {
        logSystem(`Network Error: ${error}`, 'error');
        btn.innerText = "Stop";
        btn.disabled = false;
    }
}

async function startAll() {
    logSystem('Initiating Start All sequence...');
    const services = ['http', 'ftp', 'ssh'];
    for (const service of services) {
        // Only start if not already running (checked by checking UI state or simply firing request)
        // We'll just fire the start request, backend handles "already running" gracefully? 
        // Backend returns "service already running" if so.
        await toggleService(service);
        // Small delay to prevent race conditions or UI flickering
        await new Promise(r => setTimeout(r, 500));
    }
}

async function stopAll() {
    logSystem('Initiating Stop All sequence...');
    const services = ['http', 'ftp', 'ssh'];
    for (const service of services) {
        await stopServiceReq(service);
        await new Promise(r => setTimeout(r, 500));
    }
}

async function clearLogs() {
    try {
        await fetch('/api/logs/clear', { method: 'POST' });
        attackers.clear();
        displayAttackers();
    } catch (error) {
        console.error('Failed to clear logs', error);
    }
}

async function fetchStatus() {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();

        for (const [service, running] of Object.entries(data.status)) {
            updateServiceUI(service, running, data.ports[service]);
        }
        updateStats(data.stats);
    } catch (error) {
        logSystem('Failed to fetch initial status', 'error');
    }
}


async function handleFileUpload(event, service) {
    const files = event.target.files;
    if (!files || files.length === 0) return;

    const fileLabel = document.getElementById(`file-label-${service}`);
    
    // Handle multiple files for FTP
    if (service === 'ftp' && files.length > 0) {
        fileLabel.textContent = `Uploading ${files.length} file(s)...`;
        
        let successCount = 0;
        for (let i = 0; i < files.length; i++) {
            const formData = new FormData();
            formData.append('file', files[i]);
            
            try {
                const response = await fetch('/api/upload', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                if (response.ok) {
                    successCount++;
                    logSystem(`Uploaded FTP file: ${files[i].name}`);
                } else {
                    logSystem(`Upload failed for ${files[i].name}: ${data.error}`, 'error');
                }
            } catch (error) {
                logSystem(`Upload error for ${files[i].name}: ${error}`, 'error');
            }
        }
        
        fileLabel.textContent = `${successCount} file(s) uploaded`;
        return;
    }
    
    // Single file for HTTP
    const file = files[0];
    const formData = new FormData();
    formData.append('file', file);

    try {
        fileLabel.textContent = "Uploading...";

        const response = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (response.ok) {
            fileLabel.textContent = file.name;
            fileLabel.dataset.filepath = data.filepath;
            logSystem(`Uploaded HTML file: ${file.name}`);
        } else {
            fileLabel.textContent = "Error";
            logSystem(`Upload failed: ${data.error}`, 'error');
        }

    } catch (error) {
        logSystem(`Upload error: ${error}`, 'error');
    }
}

// UI Helpers
function updateServiceUI(service, running, port) {
    const startBtn = document.getElementById(`btn-${service}`);
    const stopBtn = startBtn.parentElement.querySelector('.btn-stop');

    const statusText = document.getElementById(`status-text-${service}`);
    const dot = document.getElementById(`dot-${service}`);
    const portInput = document.getElementById(`port-${service}`);

    if (running) {
        // RUNNING STATE
        startBtn.disabled = true;
        startBtn.innerText = "Start"; // Reset text

        stopBtn.disabled = false;
        stopBtn.innerText = "Stop";

        statusText.textContent = 'Running';
        statusText.classList.add('running'); // Makes it green

        dot.classList.remove('red');
        dot.classList.add('green');

        if (portInput) portInput.disabled = true; // Lock port while running
    } else {
        // STOPPED STATE
        startBtn.disabled = false;
        startBtn.innerText = "Start";

        stopBtn.disabled = true; // Can't stop if already stopped
        stopBtn.innerText = "Stop";

        statusText.textContent = 'Stopped';
        statusText.classList.remove('running'); // Back to default (red)

        dot.classList.remove('green');
        dot.classList.add('red');

        if (portInput) portInput.disabled = false; // Unlock port
    }

    if (port && portInput && !portInput.disabled) {
        // Only update port value if not disabled (user might be typing) 
        // OR prompt user. For now, sync with backend only if we really need to.
        // Actually, safer to always sync on status update to ensure truth.
        portInput.value = port;
    }
}

function updateStats(stats) {
    document.getElementById('stat-total').textContent = stats.total;
    document.getElementById('stat-http').textContent = stats.http;
    document.getElementById('stat-ftp').textContent = stats.ftp;
    document.getElementById('stat-ssh').textContent = stats.ssh;
}

function logMessage(message) {
    const terminal = document.getElementById('log-terminal');
    const entry = document.createElement('div');
    entry.className = 'log-entry';
    
    // Extract IP address from message
    const ipMatch = message.match(/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/);
    if (ipMatch) {
        const ip = ipMatch[1];
        trackAttacker(ip, message);
    }
    
    // Detect attack type and apply styling
    let logClass = '';
    if (message.includes('SQL Injection')) {
        logClass = 'attack-sql';
    } else if (message.includes('XSS Attack')) {
        logClass = 'attack-xss';
    } else if (message.includes('Command Injection')) {
        logClass = 'attack-cmd';
    } else if (message.includes('Path Traversal')) {
        logClass = 'attack-path';
    } else if (message.includes('Brute Force')) {
        logClass = 'attack-brute';
    } else if (message.includes('Login Attempt')) {
        logClass = 'attack-login';
    } else if (message.includes('FTP Download Attempt')) {
        logClass = 'attack-path';
    } else if (message.includes('Connection from')) {
        logClass = 'connection';
    }
    
    if (logClass) {
        entry.className += ` ${logClass}`;
    }
    
    // Add timestamp
    const time = new Date().toLocaleTimeString();
    entry.textContent = `[${time}] ${message}`;
    terminal.appendChild(entry);
    terminal.scrollTop = terminal.scrollHeight;
}

function logSystem(message, type = 'system') {
    const terminal = document.getElementById('log-terminal');
    const entry = document.createElement('div');
    entry.className = `log-entry ${type}`;
    const time = new Date().toLocaleTimeString();
    const fullMessage = `[${time}] [SYSTEM] ${message}`;
    entry.textContent = fullMessage;
    terminal.appendChild(entry);
    terminal.scrollTop = terminal.scrollHeight;

    // Send to backend for logging
    fetch('/api/log', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: fullMessage })
    }).catch(err => console.error("Failed to sync log:", err));
}

// Track attacker activity
function trackAttacker(ip, message) {
    if (!attackers.has(ip)) {
        attackers.set(ip, { count: 0, attacks: [] });
    }
    
    const attacker = attackers.get(ip);
    attacker.count++;
    
    // Categorize attack
    let attackType = 'Connection';
    if (message.includes('SQL Injection')) {
        attackType = 'SQL Injection';
    } else if (message.includes('XSS Attack')) {
        attackType = 'XSS Attack';
    } else if (message.includes('Command Injection')) {
        attackType = 'Command Injection';
    } else if (message.includes('Path Traversal')) {
        attackType = 'Path Traversal';
    } else if (message.includes('Brute Force')) {
        attackType = 'Brute Force';
    } else if (message.includes('Login Attempt')) {
        attackType = 'Login Attempt';
    } else if (message.includes('FTP Download Attempt')) {
        attackType = 'FTP Download Attempt';
    }
    
    if (!attacker.attacks.includes(attackType)) {
        attacker.attacks.push(attackType);
    }
    
    displayAttackers();
}

// Update attackers table display
function displayAttackers() {
    const tbody = document.getElementById('attackers-table-body');
    const statAttackers = document.getElementById('stat-attackers');
    
    if (attackers.size === 0) {
        tbody.innerHTML = '<tr><td colspan="3" style="text-align: center; color: #999;">No attacks detected yet</td></tr>';
        statAttackers.textContent = '0';
        return;
    }
    
    statAttackers.textContent = attackers.size;
    
    tbody.innerHTML = '';
    const sortedAttackers = Array.from(attackers.entries())
        .sort((a, b) => b[1].count - a[1].count);
    
    sortedAttackers.forEach(([ip, data]) => {
        const row = document.createElement('tr');
        row.className = data.attacks.length > 1 ? 'attacker-critical' : 'attacker-warning';
        
        const attackPatterns = data.attacks.join(', ');
        
        row.innerHTML = `
            <td class="attacker-ip">${ip}</td>
            <td class="attacker-count">${data.count}</td>
            <td class="attacker-patterns">${attackPatterns}</td>
        `;
        tbody.appendChild(row);
    });
}
