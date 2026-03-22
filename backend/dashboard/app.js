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
      const risk = data.risk_score ?? 0;

      const status = data.status ?? "PASS";

      /* Update metric cards */
      const set = (id, value) => {
        const el = document.getElementById(id);
        if (!el) return;

        el.innerText = value;

        if (value > 0) {
          el.style.color = "#ff4d6d";
        } else {
          el.style.color = "#2aff8f";
        }
      };

      set("secrets", secrets);
      set("sast", sast);
      set("cve", cve);
      set("iac", iac);

      /* Risk Score */
      const riskScoreEl = document.getElementById("riskScore");

      if (riskScoreEl) {
        riskScoreEl.innerText = risk;

        if (risk > 50) {
          riskScoreEl.style.color = "#ff4d6d";
        } else {
          riskScoreEl.style.color = "#2aff8f";
        }
      }

      /* Pipeline Status Badge */
      const badge = document.getElementById("pipeline-status");
      if (badge) {
      badge.innerText = status === "FAIL" ? "BLOCKED" : "SECURE";
      badge.style.background = status === "FAIL" ? "#ff4d6d" : "#2aff8f";
      }

      renderCharts(secrets, sast, cve, iac);

    })
    .catch(err => console.error("Status API error:", err));


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

        tr.style.color =
          r.status === "FAIL"
            ? "#ff4d6d"
            : "#2aff8f";

        tbody.appendChild(tr);

      });

    })
    .catch(err => console.error("History API error:", err));


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

});


/* CHARTS */

function renderCharts(secrets, sast, cve, iac) {

  const total = secrets + sast + cve + iac;
  const safe = total === 0 ? 4 : Math.max(0, 4 - total);

  /* Risk Chart */

  new Chart(document.getElementById("riskChart"), {

    type: "doughnut",

    data: {
      labels: ["Safe", "Risk"],
      datasets: [{
        data: [safe, total],
        backgroundColor: ["#2aff8f", "#ff4d6d"]
      }]
    },

    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: "70%",
      plugins: {
        legend: {
          labels: { color: "#ffffff" }
        }
      }
    }

  });


  /* Issue Distribution Chart */

  new Chart(document.getElementById("barChart"), {

    type: "bar",

    data: {
      labels: ["Secrets", "SAST", "CVEs", "IaC"],
      datasets: [{
        label: "Issues",
        data: [secrets, sast, cve, iac],
        backgroundColor: [
          "#ff4d6d",
          "#9f7aea",
          "#ff9f1c",
          "#2ec4b6"
        ]
      }]
    },

    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          labels: { color: "#ffffff" }
        }
      },
      scales: {
        x: {
          ticks: { color: "#ffffff" }
        },
        y: {
          ticks: { color: "#ffffff" }
        }
      }
    }

  });

}


/* REPORT VIEWER */

function loadReport(type){

  fetch("/api/report/" + type)

  .then(res => res.json())

  .then(data => {

    const output = document.getElementById("report-content");

    if(!output) return;

    output.textContent = data.data;

  })

  .catch(err => {

    console.error("Report loading error:", err);

  });

}
