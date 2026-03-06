/* PipeGuard Dashboard JS */

document.addEventListener("DOMContentLoaded", () => {

  /* STATUS */
  fetch("/api/status")
    .then(res => res.json())
    .then(data => {

      const secrets = data.secrets ?? 0;
      const sast = data.sast ?? 0;
      const cve = data.cve ?? 0;
      const iac = data.iac ?? 0;

      const set = (id, failed) => {
        const el = document.getElementById(id);
        if (!el) return;
        el.innerText = failed ? "FAIL" : "PASS";
        el.style.color = failed ? "#ff4d6d" : "#2aff8f";
      };

      set("secrets", secrets);
      set("sast", sast);
      set("cve", cve);
      set("iac", iac);

      const failedCount = [secrets, sast, cve, iac].filter(v => v).length;

      const badge = document.getElementById("pipeline-status");
      if (badge) {
        badge.innerText = failedCount ? "BLOCKED" : "SECURE";
        badge.style.background = failedCount ? "#ff4d6d" : "#2aff8f";
      }

      renderCharts(secrets, sast, cve, iac);
    })
    .catch(err => console.error("Status API error:", err));


  /* CHARTS */
  function renderCharts(secrets, sast, cve, iac) {

    const failed = [secrets, sast, cve, iac].filter(v => v).length;

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
        responsive: true,
        maintainAspectRatio: false,
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
          data: [secrets, sast, cve, iac],
          backgroundColor: "#9f7aea"
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { labels: { color: "#ffffff" } }
        }
      }
    });
  }


  /* SIDEBAR NAVIGATION */
  document.querySelectorAll(".sidebar li").forEach(item => {
    item.addEventListener("click", () => {

      document.querySelectorAll(".sidebar li")
        .forEach(li => li.classList.remove("active"));

      item.classList.add("active");

      const view = item.dataset.view;
      document.querySelectorAll(".view")
        .forEach(v => v.classList.add("hidden"));

      const target = document.getElementById(`view-${view}`);
      if (target) target.classList.remove("hidden");
    });
  });


  /* PIPELINE HISTORY */
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

});
