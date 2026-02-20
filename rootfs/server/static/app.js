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

  setInterval(function () {
    refreshStatus();
    refreshAccess();
  }, POLL_MS);
})();
