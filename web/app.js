let protocolChartInstance = null;
let topTalkersChartInstance = null;
let sizeChartInstance = null;
let portChartInstance = null;
let globalPackets = [];

document.addEventListener("DOMContentLoaded", () => {
  const pcapSelect = document.getElementById("pcapSelect");
  const refreshBtn = document.getElementById("refreshBtn");
  const searchInput = document.getElementById("packetSearch");

  loadAnalysis(pcapSelect.value);

  pcapSelect.addEventListener("change", () => loadAnalysis(pcapSelect.value));
  refreshBtn.addEventListener("click", () => loadAnalysis(pcapSelect.value));
  
  if (searchInput) {
    searchInput.addEventListener("input", (e) => filterPackets(e.target.value));
  }
});

async function loadAnalysis(filename) {
  try {
    const res = await fetch(`/api/analyze?file=${encodeURIComponent(filename)}`);
    if (!res.ok) throw new Error(`HTTP error ${res.status}`);
    const data = await res.json();
    renderDashboard(data);
  } catch (err) {
    console.error("Failed to load analysis:", err);
    alert(`Could not fetch analysis data: ${err.message}`);
  }
}

function renderDashboard(data) {
  const s = data.summary;
  
  // Update Metrics
  document.getElementById("metricPackets").textContent = Number(s.total_packets).toLocaleString();
  document.getElementById("metricBytes").textContent = `${(s.total_bytes / 1024).toFixed(1)} KB`;
  document.getElementById("metricRate").textContent = `${s.packets_per_second} pps`;
  document.getElementById("metricThroughput").textContent = `${s.throughput_kbps} Kbps`;
  document.getElementById("metricAlerts").textContent = data.total_alerts;
  
  const alertBadge = document.getElementById("alertCountBadge");
  if (alertBadge) {
    alertBadge.textContent = `${data.total_alerts} Anomalies`;
  }

  // Render Charts
  renderProtocolChart(data.protocol_distribution);
  renderTopTalkersChart(data.top_source_ips);
  renderSizeChart(data.packet_size_buckets);
  renderPortChart(data.top_ports);

  // Render Alerts
  renderAlerts(data.security_alerts);

  // Render Packets
  globalPackets = data.recent_packets || [];
  renderPackets(globalPackets);
}

function renderProtocolChart(protocols) {
  const ctx = document.getElementById("protocolChart").getContext("2d");
  if (protocolChartInstance) protocolChartInstance.destroy();

  const labels = protocols.map(p => p.protocol);
  const counts = protocols.map(p => p.packet_count);
  const colors = [
    "#38bdf8", "#818cf8", "#10b981", "#f59e0b", "#ec4899", "#a855f7", "#64748b"
  ];

  protocolChartInstance = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: labels,
      datasets: [{
        data: counts,
        backgroundColor: colors.slice(0, labels.length),
        borderColor: "#131c31",
        borderWidth: 2
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "right",
          labels: { color: "#cbd5e1", font: { family: "Plus Jakarta Sans", size: 11 } }
        }
      }
    }
  });
}

function renderTopTalkersChart(talkers) {
  const ctx = document.getElementById("topTalkersChart").getContext("2d");
  if (topTalkersChartInstance) topTalkersChartInstance.destroy();

  const labels = talkers.map(t => t.ip);
  const counts = talkers.map(t => t.packets);

  topTalkersChartInstance = new Chart(ctx, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [{
        label: "Packets",
        data: counts,
        backgroundColor: "#38bdf8",
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        x: { ticks: { color: "#94a3b8", font: { family: "JetBrains Mono", size: 10 } } },
        y: { ticks: { color: "#94a3b8" }, grid: { color: "#1e293b" } }
      }
    }
  });
}

function renderSizeChart(buckets) {
  const ctx = document.getElementById("sizeChart").getContext("2d");
  if (sizeChartInstance) sizeChartInstance.destroy();

  const labels = Object.keys(buckets);
  const values = Object.values(buckets);

  sizeChartInstance = new Chart(ctx, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [{
        label: "Count",
        data: values,
        backgroundColor: "#818cf8",
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: "#94a3b8" } },
        y: { ticks: { color: "#94a3b8" }, grid: { color: "#1e293b" } }
      }
    }
  });
}

function renderPortChart(ports) {
  const ctx = document.getElementById("portChart").getContext("2d");
  if (portChartInstance) portChartInstance.destroy();

  const labels = ports.map(p => `Port ${p.port}`);
  const values = ports.map(p => p.count);

  portChartInstance = new Chart(ctx, {
    type: "bar",
    indexAxis: "y",
    data: {
      labels: labels,
      datasets: [{
        label: "Hits",
        data: values,
        backgroundColor: "#10b981",
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: "#94a3b8" }, grid: { color: "#1e293b" } },
        y: { ticks: { color: "#94a3b8", font: { family: "JetBrains Mono" } } }
      }
    }
  });
}

function renderAlerts(alerts) {
  const tbody = document.getElementById("alertsTableBody");
  if (!alerts || alerts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="text-center" style="color: #10b981; padding: 2rem;">✅ Zero security anomalies detected in this capture. Traffic profile is clean.</td></tr>`;
    return;
  }

  tbody.innerHTML = alerts.map(a => {
    let sevBadge = "badge-danger";
    if (a.severity === "MEDIUM") sevBadge = "badge-warning";
    if (a.severity === "LOW") sevBadge = "badge-primary";

    return `
      <tr>
        <td><span class="badge ${sevBadge}">${a.severity}</span></td>
        <td><code>${a.type}</code></td>
        <td><code>${a.src_ip}</code></td>
        <td>${a.description}</td>
        <td style="font-family: var(--font-mono); font-size: 0.8rem; color: #94a3b8;">${a.timestamp}s</td>
      </tr>
    `;
  }).join("");
}

function renderPackets(packets) {
  const tbody = document.getElementById("packetsTableBody");
  if (!packets || packets.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-center">No packet frames available.</td></tr>`;
    return;
  }

  tbody.innerHTML = packets.map((p, idx) => `
    <tr>
      <td style="color: #64748b;">${idx + 1}</td>
      <td style="font-family: var(--font-mono); font-size: 0.8rem;">${p.timestamp}</td>
      <td><span class="badge badge-primary">${p.protocol}</span></td>
      <td><code>${p.ip_src || '-'}:${p.src_port || '-'}</code></td>
      <td><code>${p.ip_dst || '-'}:${p.dst_port || '-'}</code></td>
      <td style="font-size: 0.75rem; color: #cbd5e1;">${(p.tcp_flags || []).join(", ") || "-"}</td>
      <td style="font-family: var(--font-mono);">${p.orig_len} B</td>
    </tr>
  `).join("");
}

function filterPackets(query) {
  const q = query.toLowerCase().trim();
  if (!q) {
    renderPackets(globalPackets);
    return;
  }
  const filtered = globalPackets.filter(p => 
    (p.ip_src && p.ip_src.includes(q)) ||
    (p.ip_dst && p.ip_dst.includes(q)) ||
    (p.protocol && p.protocol.toLowerCase().includes(q)) ||
    (p.src_port && String(p.src_port).includes(q)) ||
    (p.dst_port && String(p.dst_port).includes(q))
  );
  renderPackets(filtered);
}
