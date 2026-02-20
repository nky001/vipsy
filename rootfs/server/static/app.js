(function () {
  var POLL_MS = 20000;

  function setText(id, val) {
    var el = document.getElementById(id);
    if (el) el.textContent = val;
  }

  function setClass(id, cls) {
    var el = document.getElementById(id);
    if (el) el.className = cls;
  }

  var basePath = (window.INGRESS_ENTRY || "").replace(/\/$/, "") + "/";

  function refreshAccess() {
    fetch(basePath + "api/access")
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var local = d.local || {};
        var ext = d.external || {};
        var ha = d.ha_core || {};

        setText("local-ip", local.ip || "\u2014");
        setText("local-status", local.reachable ? "\u2713 Reachable" : "\u2715 Not Reachable");
        setClass("local-status", "access-status " + (local.reachable ? "access-status--ok" : "access-status--err"));

        setText("ext-ip", ext.public_ip || "Unknown");
        setText("ext-domain", ext.domain || "\u2014 (not set)");
        if (document.getElementById("ext-status")) {
          setText("ext-status", ext.reachable ? "\u2713 Reachable" : "\u2715 Not Reachable");
          setClass("ext-status", "access-status " + (ext.reachable ? "access-status--ok" : "access-status--err"));
        }

        if (document.getElementById("ha-status")) {
          setText("ha-status", (ha.reachable ? "\u25cf" : "\u25cf") + " " + (ha.reachable ? "Reachable" : "Not Reachable"));
          setClass("ha-status", ha.reachable ? "chip chip--green" : "chip chip--red");
        }
      })
      .catch(function () {});
  }

  function refreshStatus() {
    fetch(basePath + "api/status")
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var badge = document.getElementById("run-badge");
        if (badge) {
          var up = d.caddy === true;
          badge.textContent = up ? "Running" : "Stopped";
          badge.className = "badge badge--" + (up ? "green" : "red");
        }
        var ts = new Date().toISOString().replace("T", " ").slice(0, 16) + " UTC";
        var rf = document.getElementById("last-refresh");
        if (rf) rf.textContent = ts;
      })
      .catch(function () {});
  }

  function refreshTunnel() {
    var card = document.getElementById("tunnel-card");
    if (!card) return;
    fetch(basePath + "api/tunnel")
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var st = document.getElementById("tunnel-status");
        if (st) {
          if (d.healthy) {
            st.textContent = "\u2713 Connected";
            st.className = "access-status access-status--ok";
          } else if (d.running) {
            st.textContent = "\u27f3 Connecting";
            st.className = "access-status access-status--neutral";
          } else {
            st.textContent = "\u2715 Disconnected";
            st.className = "access-status access-status--err";
          }
        }
        setText("tunnel-hostname", d.hostname || "\u2014");
        setText("tunnel-uid", d.unique_id || "\u2014");
        var urlEl = document.getElementById("tunnel-url");
        if (urlEl && d.url) {
          urlEl.textContent = d.url;
          urlEl.href = d.url;
        }
        card.className = "tunnel-card tunnel-card--" + (d.healthy ? "ok" : (d.running ? "warn" : "err"));
        var hOk = document.getElementById("tunnel-hint-ok");
        var hWarn = document.getElementById("tunnel-hint-warn");
        var hErr = document.getElementById("tunnel-hint-err");
        if (hOk) hOk.style.display = d.healthy ? "" : "none";
        if (hWarn) hWarn.style.display = (!d.healthy && d.running) ? "" : "none";
        if (hErr) hErr.style.display = (!d.healthy && !d.running) ? "" : "none";
      })
      .catch(function () {});
  }

  setInterval(function () {
    refreshStatus();
    refreshAccess();
    refreshTunnel();
  }, POLL_MS);
})();
