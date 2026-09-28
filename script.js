let totalFlows = 0;
let totalThreats = 0;
let isPaused = false;
let pulseRate = 800;
let feedInterval = null;
let incidentLog = [];

// Initialize Charts
const pieCtx = document.getElementById('threatPieChart').getContext('2d');
const threatPieChart = new Chart(pieCtx, {
    type: 'doughnut',
    data: {
        labels: ['Normal Flows', 'DDoS Floods', 'C2 Beacons', 'Port Scans'],
        datasets: [{
            data: [1, 0, 0, 0],
            backgroundColor: ['#10b981', '#ef4444', '#f59e0b', '#8b5cf6']
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: '#cbd5e1' } } }
    }
});

const velCtx = document.getElementById('trafficVelocityChart').getContext('2d');
const trafficVelocityChart = new Chart(velCtx, {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            label: 'Ingestion Rate (Pkts/s)',
            data: [],
            borderColor: '#38bdf8',
            tension: 0.3,
            fill: false
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            x: { ticks: { color: '#64748b' } },
            y: { ticks: { color: '#64748b' }, beginAtZero: true }
        },
        plugins: { legend: { labels: { color: '#cbd5e1' } } }
    }
});

function toggleIngestion() {
    isPaused = !isPaused;
    document.getElementById('toggleBtn').innerText = isPaused ? 'Resume Ingestion Feed' : 'Pause Ingestion Feed';
}

document.getElementById('speedSlider').addEventListener('input', (e) => {
    pulseRate = parseInt(e.target.value);
    document.getElementById('speedVal').innerText = pulseRate + 'ms';
    clearInterval(feedInterval);
    feedInterval = setInterval(simulateIngestion, pulseRate);
});

function addRowToFeed(src, dst, threat, conf, anomaly, isAttack) {
    totalFlows++;
    if (isAttack) totalThreats++;

    document.getElementById('statTotal').innerText = totalFlows;
    document.getElementById('statThreats').innerText = totalThreats;

    const time = new Date().toLocaleTimeString();
    incidentLog.push({ time, src, dst, threat, conf, anomaly });

    const tbody = document.getElementById('alertRows');
    const row = document.createElement('tr');
    row.innerHTML = `
        <td>${time}</td>
        <td>${src}</td>
        <td>${dst}</td>
        <td class="${isAttack ? 'badge-threat' : 'badge-clean'}">${threat}</td>
        <td>${conf}</td>
        <td>${anomaly}</td>
    `;
    tbody.insertBefore(row, tbody.firstChild);

    if (tbody.children.length > 20) tbody.removeChild(tbody.lastChild);

    // Update Velocity Chart
    const labels = trafficVelocityChart.data.labels;
    const data = trafficVelocityChart.data.datasets[0].data;
    labels.push(time);
    data.push(isAttack ? Math.floor(Math.random() * 800 + 400) : Math.floor(Math.random() * 80 + 20));
    if (labels.length > 12) {
        labels.shift();
        data.shift();
    }
    trafficVelocityChart.update();
}

function simulateIngestion() {
    if (isPaused) return;
    const randomIP = `192.168.1.${Math.floor(Math.random() * 250 + 2)}`;
    addRowToFeed(randomIP, '10.0.0.1', 'Normal Forward Flow', '99.4%', 'Standard Jitter (IAT ~0.12s)', false);
    threatPieChart.data.datasets[0].data[0]++;
    threatPieChart.update();
}

function injectThreat(type) {
    if (type === 'ddos') {
        addRowToFeed('Spoofed IP Cluster', '10.0.0.1', 'Volumetric DDoS Attack', '98.8%', 'Sudden Burst (>850 pkts/burst)', true);
        threatPieChart.data.datasets[0].data[1] += 5;
    } else if (type === 'c2') {
        addRowToFeed('10.0.0.42', '198.51.100.2', 'Botnet C2 Beaconing', '91.2%', 'Rigid Periodic Pulse (Jitter ~0.001s)', true);
        threatPieChart.data.datasets[0].data[2] += 2;
    } else if (type === 'scan') {
        addRowToFeed('192.168.1.105', '10.0.0.1', 'Port Scan (Reconnaissance)', '94.6%', 'Rapid Multi-port Probe (<50ms)', true);
        threatPieChart.data.datasets[0].data[3] += 3;
    }
    threatPieChart.update();
}

async function handlePCAPUpload(input) {
    if (!input.files || !input.files[0]) return;
    const file = input.files[0];
    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch('http://localhost:8000/upload_pcap', {
            method: 'POST',
            body: formData
        });
        const res = await response.json();
        alert(`PCAP Processed Successfully!\nTotal Ingested Packets: ${res.total_packets_read}\nThreats Detected: ${res.threats_flagged}`);
        if (res.results) {
            res.results.forEach(r => {
                const isThreat = r.predicted_threat !== 'Normal';
                addRowToFeed(r.source_ip, r.target_ip, r.predicted_threat, `${(r.confidence * 100).toFixed(1)}%`, r.signature_anomaly, isThreat);
            });
        }
    } catch (err) {
        alert('Local API server is not reachable. Make sure "python server.py" is running on your machine!');
    }
}

function exportIncidentCSV() {
    let csv = 'Timestamp,Source IP,Destination IP,Threat,Confidence,Anomaly\n';
    incidentLog.forEach(row => {
        csv += `"${row.time}","${row.src}","${row.dst}","${row.threat}","${row.conf}","${row.anomaly}"\n`;
    });
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `incident_audit_log_${Date.now()}.csv`;
    a.click();
}

feedInterval = setInterval(simulateIngestion, pulseRate);
