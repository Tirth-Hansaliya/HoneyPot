const attackers = new Map();
const serviceState = { http: false, ftp: false, ssh: false };
let socket = null;

const SERVICE_IDS = ["http", "ftp", "ssh"];

document.addEventListener("DOMContentLoaded", async () => {
    bindTabNavigation();
    drawMatrix();
    refreshIcons();

    if (!document.body.classList.contains("dashboard-page")) {
        return;
    }

    initSocket();
    bindUploadHandlers();
    await loadConfig();
    await fetchStatus();
    await fetchUploads();
});

function refreshIcons() {
    if (window.feather) {
        feather.replace();
    }
}

function bindTabNavigation() {
    const navItems = document.querySelectorAll(".nav-item");
    navItems.forEach((item) => {
        item.addEventListener("click", () => {
            const tab = item.dataset.tab;
            navItems.forEach((node) => node.classList.remove("active"));
            document.querySelectorAll(".tab-content").forEach((node) => node.classList.remove("active"));

            item.classList.add("active");
            const tabNode = document.getElementById(`tab-${tab}`);
            if (tabNode) {
                tabNode.classList.add("active");
            }
        });
    });
}

function drawMatrix() {
    const canvas = document.getElementById("matrix-canvas");
    if (!canvas) {
        return;
    }

    const ctx = canvas.getContext("2d");
    const chars = "01<>[]{}$#@%&*+=-";
    const fontSize = 14;
    let columns = 0;
    let drops = [];

    function resize() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        columns = Math.floor(canvas.width / fontSize);
        drops = Array(columns).fill(1);
    }

    function rain() {
        ctx.fillStyle = "rgba(1, 8, 6, 0.16)";
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = "#2cff69";
        ctx.font = `${fontSize}px 'Share Tech Mono'`;

        for (let i = 0; i < drops.length; i += 1) {
            const text = chars[Math.floor(Math.random() * chars.length)];
            ctx.fillText(text, i * fontSize, drops[i] * fontSize);
            if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                drops[i] = 0;
            }
            drops[i] += 1;
        }
    }

    resize();
    window.addEventListener("resize", resize);
    setInterval(rain, 45);
}

function initSocket() {
    socket = io();

    socket.on("connect", () => {
        logSystem("Socket connected. Live stream online.");
    });

    socket.on("disconnect", () => {
        logSystem("Socket disconnected.", "error");
    });

    socket.on("status_update", (data) => {
        updateServiceUI(data.service, data.running, data.port);
        updateHeaderActive();
    });

    socket.on("stats_update", (data) => {
        updateStats(data);
    });

    socket.on("new_log", (data) => {
        logMessage(data.message);
    });

    socket.on("clear_logs", () => {
        const terminal = document.getElementById("log-terminal");
        if (terminal) {
            terminal.innerHTML = '<div class="log-entry system">Logs cleared...</div>';
        }
    });
}

function bindUploadHandlers() {
    const httpFile = document.getElementById("file-input-http");
    const ftpFile = document.getElementById("file-input-ftp");

    if (httpFile) {
        httpFile.addEventListener("change", (event) => handleFileUpload(event, "http"));
    }

    if (ftpFile) {
        ftpFile.addEventListener("change", (event) => handleFileUpload(event, "ftp"));
    }
}

async function apiFetch(url, options = {}) {
    return fetch(url, options);
}

async function loadConfig() {
    const response = await apiFetch("/api/config");
    if (!response.ok) {
        return;
    }

    const data = await response.json();
    populateBannerSelect("http", data.banners.http || []);
    populateBannerSelect("ftp", data.banners.ftp || []);
    populateBannerSelect("ssh", data.banners.ssh || []);
}

function populateBannerSelect(service, options) {
    const select = document.getElementById(`banner-${service}`);
    if (!select) {
        return;
    }

    select.innerHTML = "";
    options.forEach((option) => {
        const node = document.createElement("option");
        node.value = option.id;
        node.textContent = option.label;
        select.appendChild(node);
    });

    const custom = document.createElement("option");
    custom.value = "custom";
    custom.textContent = "Custom Banner";
    select.appendChild(custom);
}

async function fetchStatus() {
    const response = await apiFetch("/api/status");
    if (!response.ok) {
        return;
    }

    const data = await response.json();
    Object.entries(data.status || {}).forEach(([service, running]) => {
        updateServiceUI(service, running, data.ports?.[service]);
        const select = document.getElementById(`banner-${service}`);
        if (select && data.selected_banners?.[service]) {
            select.value = data.selected_banners[service];
        }
    });

    updateStats(data.stats || {});
    updateHeaderActive();
}

async function fetchUploads() {
    const response = await apiFetch("/api/uploads/list");
    if (!response.ok) {
        return;
    }

    const data = await response.json();
    const list = document.getElementById("uploads-list");
    if (!list) {
        return;
    }

    if (!data.files || data.files.length === 0) {
        list.innerHTML = "<div class='upload-item'>No bait files uploaded yet.</div>";
        return;
    }

    list.innerHTML = "";
    data.files.forEach((file) => {
        const row = document.createElement("div");
        row.className = "upload-item";
        row.textContent = `${file.name} (${file.size} bytes)`;
        list.appendChild(row);
    });
}

function setButtonState(button, icon, label) {
    if (!button) {
        return;
    }
    button.innerHTML = `<i data-feather="${icon}"></i>${label}`;
    refreshIcons();
}

async function toggleService(service) {
    const startBtn = document.getElementById(`btn-${service}`);
    const portInput = document.getElementById(`port-${service}`);
    if (!startBtn || !portInput) {
        return;
    }

    const payload = {
        port: Number(portInput.value),
        banner_id: (document.getElementById(`banner-${service}`)?.value || "").trim(),
        custom_banner: (document.getElementById(`custom-banner-${service}`)?.value || "").trim(),
    };

    if (service === "http") {
        payload.html_file = document.getElementById("file-label-http")?.dataset.filepath || null;
    }

    startBtn.disabled = true;
    setButtonState(startBtn, "loader", "Starting");

    try {
        const response = await apiFetch(`/api/start/${service}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });

        const data = await response.json();
        if (!response.ok) {
            logSystem(`Failed to start ${service}: ${data.error || "unknown error"}`, "error");
        } else {
            logSystem(`${service.toUpperCase()} started on port ${data.port}.`);
        }
    } catch (error) {
        logSystem(`Network error while starting ${service}: ${error}`, "error");
    } finally {
        updateServiceUI(service, serviceState[service], Number(portInput.value));
    }
}

async function stopServiceReq(service) {
    const stopBtn = document.getElementById(`btn-stop-${service}`);
    if (!stopBtn) {
        return;
    }

    stopBtn.disabled = true;
    setButtonState(stopBtn, "loader", "Stopping");

    try {
        const response = await apiFetch(`/api/stop/${service}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({}),
        });

        const data = await response.json();
        if (!response.ok) {
            logSystem(`Failed to stop ${service}: ${data.error || "unknown error"}`, "error");
        } else {
            logSystem(`${service.toUpperCase()} stopped.`);
        }
    } catch (error) {
        logSystem(`Network error while stopping ${service}: ${error}`, "error");
    } finally {
        updateServiceUI(service, serviceState[service], Number(document.getElementById(`port-${service}`)?.value || 0));
    }
}

async function startAll() {
    for (const service of SERVICE_IDS) {
        await toggleService(service);
        await delay(300);
    }
}

async function stopAll() {
    for (const service of SERVICE_IDS) {
        await stopServiceReq(service);
        await delay(300);
    }
}

function delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

async function clearLogs() {
    const response = await apiFetch("/api/logs/clear", { method: "POST" });
    if (!response.ok) {
        logSystem("Failed to clear logs.", "error");
        return;
    }

    attackers.clear();
    displayAttackers();
}

async function handleFileUpload(event, service) {
    const files = event.target.files;
    if (!files || files.length === 0) {
        return;
    }

    const label = document.getElementById(`file-label-${service}`);
    if (label) {
        label.textContent = `Uploading ${files.length} file(s)...`;
    }

    let success = 0;
    for (const file of files) {
        const body = new FormData();
        body.append("file", file);

        try {
            const response = await apiFetch("/api/upload", { method: "POST", body });
            const data = await response.json();

            if (response.ok) {
                success += 1;
                if (service === "http" && label) {
                    label.dataset.filepath = data.filepath;
                }
                logSystem(`Uploaded file: ${data.name}`);
            } else {
                logSystem(`Upload failed for ${file.name}: ${data.error || "unknown error"}`, "error");
            }
        } catch (error) {
            logSystem(`Upload error for ${file.name}: ${error}`, "error");
        }
    }

    if (label) {
        if (service === "http" && success > 0) {
            label.textContent = files[0].name;
        } else {
            label.textContent = `${success}/${files.length} uploaded`;
        }
    }

    await fetchUploads();
}

function updateServiceUI(service, running, port) {
    const startBtn = document.getElementById(`btn-${service}`);
    const stopBtn = document.getElementById(`btn-stop-${service}`);
    const statusText = document.getElementById(`status-text-${service}`);
    const dot = document.getElementById(`dot-${service}`);
    const portInput = document.getElementById(`port-${service}`);

    if (!startBtn || !stopBtn || !statusText || !dot || !portInput) {
        return;
    }

    serviceState[service] = Boolean(running);
    startBtn.disabled = serviceState[service];
    stopBtn.disabled = !serviceState[service];
    portInput.disabled = serviceState[service];

    setButtonState(startBtn, "play", "Start");
    setButtonState(stopBtn, "square", "Stop");

    statusText.textContent = serviceState[service] ? "Running" : "Stopped";
    statusText.classList.toggle("running", serviceState[service]);
    dot.classList.toggle("green", serviceState[service]);
    dot.classList.toggle("red", !serviceState[service]);

    if (!serviceState[service] && Number.isFinite(port) && port > 0) {
        portInput.value = String(port);
    }
}

function updateStats(stats) {
    setText("stat-total", stats.total || 0);
    setText("stat-http", stats.http || 0);
    setText("stat-ftp", stats.ftp || 0);
    setText("stat-ssh", stats.ssh || 0);
    setText("header-total", stats.total || 0);
}

function setText(id, value) {
    const node = document.getElementById(id);
    if (node) {
        node.textContent = String(value);
    }
}

function updateHeaderActive() {
    const activeCount = Object.values(serviceState).filter(Boolean).length;
    setText("header-active", activeCount);
}

function logMessage(message) {
    const terminal = document.getElementById("log-terminal");
    if (!terminal) {
        return;
    }

    const row = document.createElement("div");
    row.className = "log-entry";

    if (message.includes("[Nmap Scan Detection]")) {
        row.classList.add("attack-scan");
    } else if (message.includes("[Tool Detection]") || message.includes("[Scanner Detection]")) {
        row.classList.add("attack-cmd");
    } else if (message.includes("SQL Injection")) {
        row.classList.add("attack-sql");
    } else if (message.includes("XSS")) {
        row.classList.add("attack-xss");
    } else if (message.includes("Path Traversal")) {
        row.classList.add("attack-path");
    } else if (message.includes("Connection from")) {
        row.classList.add("connection");
    }

    row.textContent = message;
    terminal.appendChild(row);
    terminal.scrollTop = terminal.scrollHeight;

    const ipMatch = message.match(/(\d{1,3}(?:\.\d{1,3}){3})/);
    if (ipMatch) {
        trackAttacker(ipMatch[1], message);
    }
}

function logSystem(message, type = "system") {
    const terminal = document.getElementById("log-terminal");
    const fullMessage = `[SYSTEM] ${message}`;

    if (terminal) {
        const row = document.createElement("div");
        row.className = `log-entry ${type}`;
        row.textContent = fullMessage;
        terminal.appendChild(row);
        terminal.scrollTop = terminal.scrollHeight;
    }

    apiFetch("/api/log", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: fullMessage }),
    }).catch(() => {
        return undefined;
    });
}

function trackAttacker(ip, message) {
    if (!attackers.has(ip)) {
        attackers.set(ip, {
            count: 0,
            attacks: [],
            threatScore: 0,
            bruteForce: "Low",
            intent: "Unknown",
            credentialAttempts: 0,
            mlBruteConfidence: 0,
            mlAttemptCount: 0,
            mlBruteDetected: false,
            attemptTimestamps: [],
        });
    }

    const record = attackers.get(ip);
    record.count += 1;

    const markers = [
        "SQL Injection",
        "XSS",
        "Path Traversal",
        "Command Injection",
        "Credential",
        "Nmap Scan",
        "Tool Detection",
        "Scanner Detection",
        "Malware download",
    ];

    markers.forEach((marker) => {
        if (message.includes(marker) && !record.attacks.includes(marker)) {
            record.attacks.push(marker);
        }
    });

    if (record.attacks.length === 0) {
        record.attacks.push("Connection");
    }

    updateMLScores(record, message);
    displayAttackers();
}

function updateMLScores(record, message) {
    const lowerMessage = message.toLowerCase();

    const threatKeywords = ["SQL", "XSS", "Command", "Injection", "Malware", "backdoor", "shell", "exploit"];
    let threatScore = Math.min(100, Math.floor(record.count * 5));

    threatKeywords.forEach((keyword) => {
        if (message.includes(keyword)) {
            threatScore = Math.min(100, threatScore + 15);
        }
    });
    record.threatScore = threatScore;

    const credentialIndicators = [
        "credential capture",
        "credential harvest",
        "username=",
        "password=",
        "auth fail",
        "invalid user",
        "login failed",
    ];
    const sawCredentialAttempt = credentialIndicators.some((token) => lowerMessage.includes(token));
    if (sawCredentialAttempt) {
        record.credentialAttempts += 1;
        registerAttemptTimestamp(record);
    }

    const mlBrute = parseMLBruteLine(message);
    if (mlBrute) {
        record.mlBruteConfidence = Math.max(record.mlBruteConfidence, mlBrute.confidencePercent);
        record.mlAttemptCount = Math.max(record.mlAttemptCount, mlBrute.attemptCount);
        record.mlBruteDetected = record.mlBruteDetected || mlBrute.isBruteForce;
        record.credentialAttempts = Math.max(record.credentialAttempts, mlBrute.attemptCount);
        registerAttemptTimestamp(record);
    }

    const computedBruteLevel = classifyBruteForceLevel(record);
    record.bruteForce = maxSeverityLevel(record.bruteForce, computedBruteLevel);

    const intentKeywords = {
        Recon: ["whoami", "id", "uname", "ifconfig", "netstat", "cat /etc", "ls", "pwd", "nmap"],
        Persistence: ["crontab", ".bashrc", "authorized_keys", "systemd"],
        Exfiltration: ["wget", "curl", "scp", "nc", "ftp", "rsync"],
        Destructive: ["rm -rf", "shred", "dd", "mkfs", "chmod"],
        Malware: ["chmod +x", "python", "base64"],
    };

    let detectedIntent = "Normal";
    for (const [intentType, keywords] of Object.entries(intentKeywords)) {
        if (keywords.some((keyword) => message.includes(keyword))) {
            detectedIntent = intentType;
            break;
        }
    }
    record.intent = detectedIntent;
}

function parseMLBruteLine(message) {
    const match = message.match(/\[ML Brute Force\].*?attempt=(\d+).*?is_brute_force=(true|false).*?confidence=(\d+)%/i);
    if (!match) {
        return null;
    }

    return {
        attemptCount: Number(match[1]),
        isBruteForce: String(match[2]).toLowerCase() === "true",
        confidencePercent: Number(match[3]),
    };
}

function classifyBruteForceLevel(record) {
    const attemptsIn30s = countAttemptsInWindow(record, 30_000);
    const attemptsIn60s = countAttemptsInWindow(record, 60_000);
    const attemptsIn120s = countAttemptsInWindow(record, 120_000);

    // High: many credential attempts in a short burst.
    if (
        attemptsIn30s >= 8 ||
        attemptsIn60s >= 12 ||
        attemptsIn120s >= 18 ||
        record.mlBruteDetected ||
        record.mlBruteConfidence >= 70 ||
        record.mlAttemptCount >= 10
    ) {
        return "High";
    }

    // Medium: suspicious repeated attempts within short windows.
    if (
        attemptsIn30s >= 4 ||
        attemptsIn60s >= 6 ||
        attemptsIn120s >= 10 ||
        record.mlBruteConfidence >= 40 ||
        record.mlAttemptCount >= 5 ||
        record.credentialAttempts >= 5
    ) {
        return "Medium";
    }

    // Low: initial credential probing or small number of attempts.
    if (attemptsIn120s >= 1 || record.credentialAttempts >= 1) {
        return "Low";
    }

    return "Low";
}

function registerAttemptTimestamp(record) {
    const now = Date.now();
    record.attemptTimestamps.push(now);

    // Keep only recent history used by severity windows.
    const minTime = now - 120_000;
    while (record.attemptTimestamps.length > 0 && record.attemptTimestamps[0] < minTime) {
        record.attemptTimestamps.shift();
    }
}

function countAttemptsInWindow(record, windowMs) {
    const now = Date.now();
    const minTime = now - windowMs;
    let count = 0;

    for (let i = record.attemptTimestamps.length - 1; i >= 0; i -= 1) {
        if (record.attemptTimestamps[i] >= minTime) {
            count += 1;
        } else {
            break;
        }
    }

    return count;
}

function maxSeverityLevel(currentLevel, nextLevel) {
    const rank = { Low: 1, Medium: 2, High: 3 };
    const current = rank[currentLevel] || 1;
    const next = rank[nextLevel] || 1;
    return next > current ? nextLevel : currentLevel;
}

function displayAttackers() {
    const tbody = document.getElementById("attackers-table-body");
    const totalNode = document.getElementById("stat-attackers");
    if (!tbody || !totalNode) {
        return;
    }

    totalNode.textContent = String(attackers.size);

    if (attackers.size === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#88aa88;">No attackers recorded yet</td></tr>';
        return;
    }

    tbody.innerHTML = "";
    const sorted = Array.from(attackers.entries()).sort((a, b) => b[1].count - a[1].count);
    sorted.forEach(([ip, info]) => {
        const row = document.createElement("tr");
        row.innerHTML = `<td class='attacker-ip'>${ip}</td><td class='attacker-count'>${info.count}</td><td class='attacker-patterns'>${info.attacks.join(", ")}</td><td class='attacker-ml-threat'>${info.threatScore}</td><td class='attacker-ml-brute'>${info.bruteForce}</td><td class='attacker-ml-intent'>${info.intent}</td>`;
        tbody.appendChild(row);
    });
}
