let vulnChart = null;
let trendChart = null;
let severityChart = null;

function startScan() {
    const target = document.getElementById("targetInput").value;
    const eventStream = document.getElementById("eventStream");
    const alertBox = document.getElementById("alertBox");
    const progressText = document.getElementById("progressText");

    eventStream.innerHTML = "";
    alertBox.innerHTML = "";
    progressText.innerText = "0%";

    let progress = 0;
    const progressInterval = setInterval(() => {
        progress += 5;
        progressText.innerText = progress + "%";
        if (progress >= 100) clearInterval(progressInterval);
    }, 200);

    fetch("/api/scan", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ target })
    })
    .then(res => res.json())
    .then(data => {

        let xssCount = 0;
        let sqliCount = 0;
        let critical = 0;
        let high = 0;

        if (!data.results || data.results.length === 0) {
            eventStream.innerHTML = "[INFO] No vulnerabilities detected.";
            renderCharts(0,0,0,0);
            return;
        }

        data.results.forEach(v => {

            eventStream.innerHTML +=
                `<div>[+] ${v.type} at ${v.endpoint}</div>`;

            if (v.type.includes("SQL")) {
                sqliCount++;
                critical++;
                alertBox.innerHTML +=
                    `<div style="color:#ff0033">CRITICAL: ${v.type}</div>`;
            } else {
                xssCount++;
                high++;
                alertBox.innerHTML +=
                    `<div style="color:#ffaa00">HIGH: ${v.type}</div>`;
            }
        });

        renderCharts(xssCount, sqliCount, critical, high);
    });
}

function renderCharts(xss, sqli, critical, high) {

    if (vulnChart) vulnChart.destroy();
    if (trendChart) trendChart.destroy();
    if (severityChart) severityChart.destroy();

    // Bar Chart
    vulnChart = new Chart(document.getElementById("vulnChart"), {
        type: 'bar',
        data: {
            labels: ['XSS', 'SQL Injection'],
            datasets: [{
                label: 'Detected Vulnerabilities',
                data: [xss, sqli],
                backgroundColor: ['#00ffcc', '#ff0033']
            }]
        },
        options: {
            plugins: { legend: { labels: { color: "#00ffcc" } } },
            scales: {
                x: { ticks: { color: "#00ffcc" } },
                y: { ticks: { color: "#00ffcc" } }
            }
        }
    });

    // Trend Line Chart
    trendChart = new Chart(document.getElementById("trendChart"), {
        type: 'line',
        data: {
            labels: ['Start', 'Mid', 'End'],
            datasets: [{
                label: 'Threat Growth',
                data: [0, xss, xss + sqli],
                borderColor: '#00ffcc',
                tension: 0.4,
                fill: false
            }]
        },
        options: {
            plugins: { legend: { labels: { color: "#00ffcc" } } },
            scales: {
                x: { ticks: { color: "#00ffcc" } },
                y: { ticks: { color: "#00ffcc" } }
            }
        }
    });

    // Severity Doughnut
    severityChart = new Chart(document.getElementById("severityChart"), {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High'],
            datasets: [{
                data: [critical, high],
                backgroundColor: ['#ff0033', '#ffaa00']
            }]
        },
        options: {
            plugins: { legend: { labels: { color: "#00ffcc" } } }
        }
    });
}