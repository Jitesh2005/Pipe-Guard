/* PipeGuard Dashboard JS
   Served by FastAPI at /
   API is relative (no hardcoded host)
*/

fetch("/api/status")
  .then(res => res.json())
  .then(data => {
    // Defensive defaults
    const secrets = data.secrets ?? 0;
    const sast = data.sast ?? 0;
    const cve = data.cve ?? 0;
    const iac = data.iac ?? 0;

    const set = (id, failed) => {
      const el = document.getElementById(id);
      el.innerText = failed ? "FAIL" : "PASS";
      el.style.color = failed ? "#ff4d6d" : "#2aff8f";
    };

    set("secrets", secrets);
    set("sast", sast);
    set("cve", cve);
    set("iac", iac);

    const failedCount = [secrets, sast, cve, iac].filter(v => v).length;

    const badge = document.getElementById("pipeline-status");
    badge.innerText = failedCount ? "BLOCKED" : "SECURE";
    badge.style.background = failedCount ? "#ff4d6d" : "#2aff8f";

    renderCharts(failedCount);
  })
  .catch(err => console.error("Status API error:", err));

/* Charts */
function renderCharts(failed) {

  new Chart(document.getElementById("riskChart"), {
    type: "doughnut",
    data: {
      labels: ["Safe", "Risk"],
      datasets: [{
        data: [4 - failed, failed],
        backgroundColor: ["#2aff8f", "#ff4d6d"]
      }]
    },
    options: {
      plugins: {
        legend: { labels: { color: "#ffffff" } }
      }
    }
  });

  new Chart(document.getElementById("barChart"), {
    type: "bar",
    data: {
      labels: ["Secrets", "SAST", "CVEs", "IaC"],
      datasets: [{
        label: "Issues",
        data: [1, 1, 1, 1],
        backgroundColor: "#9f7aea"
      }]
    },
    options: {
      scales: {
        x: { ticks: { color: "#ffffff" } },
        y: { ticks: { color: "#ffffff" } }
      },
      plugins: {
        legend: { labels: { color: "#ffffff" } }
      }
    }
  });
}

/* Pipeline History */
fetch("/api/history")
  .then(res => res.json())
  .then(rows => {
    const tbody = document.querySelector("#history tbody");
    if (!tbody) return;

    rows.slice().reverse().forEach(r => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${r.timestamp}</td>
        <td>${r.status}</td>
      `;
      tr.style.color = r.status === "FAIL" ? "#ff4d6d" : "#2aff8f";
      tbody.appendChild(tr);
    });
  })
  .catch(err => console.error("History API error:", err));
