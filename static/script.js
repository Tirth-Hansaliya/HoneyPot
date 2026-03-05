const attackers = new Map();
const serviceState = { http: false, ftp: false, ssh: false };
let socket = null;

document.addEventListener("DOMContentLoaded", async () => {
    drawMatrix();
    if (window.feather) {
        feather.replace();
    }

    if (!document.body.classList.contains("dashboard-page")) {
        return;
    }

    initSocket();
    bindUploadHandlers();
    await loadConfig();
    await fetchStatus();
    await fetchUploads();
});

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
        ctx.fillStyle = "rgba(3, 12, 7, 0.10)";
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
    const response = await fetch(url, options);
    if (response.status === 401) {
        window.location.href = "/login";
        return null;
    }
    return response;
}

async function loadConfig() {
    const response = await apiFetch("/api/config");
    if (!response) {
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
    for (const option of options) {
        const node = document.createElement("option");
        node.value = option.id;
        node.textContent = option.label;
        select.appendChild(node);
    }
    const custom = document.createElement("option");
    custom.value = "custom";
    custom.textContent = "Custom Banner";
    select.appendChild(custom);
}

async function fetchStatus() {
    const response = await apiFetch("/api/status");
    if (!response) {
        return;
    }

    const data = await response.json();
    for (const [service, running] of Object.entries(data.status)) {
        updateServiceUI(service, running, data.ports[service]);
        const select = document.getElementById(`banner-${service}`);
        if (select && data.selected_banners[service]) {
            select.value = data.selected_banners[service];
        }
    }
    updateStats(data.stats);
    updateHeaderActive();
}

async function fetchUploads() {
    const response = await apiFetch("/api/uploads/list");
    if (!response) {
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
    startBtn.textContent = "...";

    try {
        const response = await apiFetch(`/api/start/${service}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });
        if (!response) {
            return;
        }
        const data = await response.json();
        if (!response.ok) {
            logSystem(`Failed to start ${service}: ${data.error || "unknown error"}`, "error");
        } else {
            logSystem(`${service.toUpperCase()} started on port ${data.port}.`);
        }
    } catch (error) {
        logSystem(`Network error while starting ${service}: ${error}`, "error");
    } finally {
        startBtn.textContent = "Start";
    }
}

async function stopServiceReq(service) {
    const stopBtn = document.querySelector(`#btn-${service}`)?.parentElement?.querySelector(".btn-stop");
    if (!stopBtn) {
        return;
    }
    stopBtn.disabled = true;
    stopBtn.textContent = "...";

    try {
        const response = await apiFetch(`/api/stop/${service}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({}),
        });
        if (!response) {
            return;
        }
        const data = await response.json();
        if (!response.ok) {
            logSystem(`Failed to stop ${service}: ${data.error || "unknown error"}`, "error");
        } else {
            logSystem(`${service.toUpperCase()} stopped.`);
        }
    } catch (error) {
        logSystem(`Network error while stopping ${service}: ${error}`, "error");
    } finally {
        stopBtn.textContent = "Stop";
    }
}

async function startAll() {
    for (const service of ["http", "ftp", "ssh"]) {
        await toggleService(service);
        await new Promise((resolve) => setTimeout(resolve, 300));
    }
}

async function stopAll() {
    for (const service of ["http", "ftp", "ssh"]) {
        await stopServiceReq(service);
        await new Promise((resolve) => setTimeout(resolve, 300));
    }
}

async function clearLogs() {
    const response = await apiFetch("/api/logs/clear", { method: "POST" });
    if (!response) {
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
            if (!response) {
                continue;
            }
            const data = await response.json();
            if (response.ok) {
                success += 1;
                if (service === "http" && label) {
                    label.dataset.filepath = data.filepath;
                }
                logSystem(`Uploaded file: ${data.name}`);
            } else {
                logSystem(`Upload failed for ${file.name}: ${data.error}`, "error");
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
    const stopBtn = startBtn?.parentElement?.querySelector(".btn-stop");
    const statusText = document.getElementById(`status-text-${service}`);
    const dot = document.getElementById(`dot-${service}`);
    const portInput = document.getElementById(`port-${service}`);
    if (!startBtn || !stopBtn || !statusText || !dot || !portInput) {
        return;
    }

    serviceState[service] = running;
    startBtn.disabled = running;
    stopBtn.disabled = !running;
    portInput.disabled = running;
    statusText.textContent = running ? "Running" : "Stopped";
    statusText.classList.toggle("running", running);
    dot.classList.toggle("green", running);
    dot.classList.toggle("red", !running);

    if (!running && port) {
        portInput.value = port;
    }
}

function updateStats(stats) {
    setText("stat-total", stats.total);
    setText("stat-http", stats.http);
    setText("stat-ftp", stats.ftp);
    setText("stat-ssh", stats.ssh);
    setText("header-total", stats.total);
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
    if (message.includes("[Tool Detection]") || message.includes("[Scanner Detection]")) {
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
    }).catch(() => {});
}

function trackAttacker(ip, message) {
    if (!attackers.has(ip)) {
        attackers.set(ip, { count: 0, attacks: [] });
    }
    const record = attackers.get(ip);
    record.count += 1;

    const markers = [
        "SQL Injection",
        "XSS",
        "Path Traversal",
        "Command Injection",
        "Credential",
        "Tool Detection",
        "Scanner Detection",
        "Malware download",
    ];

    for (const marker of markers) {
        if (message.includes(marker) && !record.attacks.includes(marker)) {
            record.attacks.push(marker);
        }
    }
    if (record.attacks.length === 0) {
        record.attacks.push("Connection");
    }

    displayAttackers();
}

function displayAttackers() {
    const tbody = document.getElementById("attackers-table-body");
    const totalNode = document.getElementById("stat-attackers");
    if (!tbody || !totalNode) {
        return;
    }

    totalNode.textContent = String(attackers.size);
    if (attackers.size === 0) {
        tbody.innerHTML = '<tr><td colspan="3" style="text-align:center;color:#88aa88;">No attackers recorded yet</td></tr>';
        return;
    }

    tbody.innerHTML = "";
    const sorted = Array.from(attackers.entries()).sort((a, b) => b[1].count - a[1].count);
    sorted.forEach(([ip, info]) => {
        const row = document.createElement("tr");
        row.className = info.attacks.length > 1 ? "attacker-critical" : "attacker-warning";
        row.innerHTML = `<td class='attacker-ip'>${ip}</td><td class='attacker-count'>${info.count}</td><td class='attacker-patterns'>${info.attacks.join(", ")}</td>`;
        tbody.appendChild(row);
    });
}
