(function () {
  var POLL_MS = 20000;
  var _loggedIn = window.LOGGED_IN;
  var _tunnelMode = "";

  function setText(id, val) {
    var el = document.getElementById(id);
    if (el) el.textContent = val;
  }

  function setClass(id, cls) {
    var el = document.getElementById(id);
    if (el) el.className = cls;
  }

  var basePath = (window.INGRESS_ENTRY || "").replace(/\/$/, "") + "/";

  function toggleStaticUrl() {
    var el = document.getElementById("tunnel-static-info");
    if (el) el.style.display = (_loggedIn && _tunnelMode === "static") ? "" : "none";
    var qRow = document.getElementById("tunnel-quick-url-row");
    if (qRow) qRow.style.display = (_tunnelMode === "quick") ? "" : "none";
  }

  function showAuthError(msg) {
    var banner = document.getElementById("auth-error-banner");
    var msgEl = document.getElementById("auth-error-msg");
    if (banner && msgEl) {
      msgEl.textContent = msg;
      banner.style.display = "";
      setTimeout(function () { banner.style.display = "none"; }, 8000);
    }
  }

  var _pollTimer = null;

  function stopAuthPoll() {
    if (_pollTimer) { clearInterval(_pollTimer); _pollTimer = null; }
  }

  function startAuthPoll(state, deadline) {
    _pollTimer = setInterval(function () {
      if (Date.now() > deadline) {
        stopAuthPoll();
        showAuthError("Sign-in timed out — please try again");
        return;
      }
      fetch(basePath + "api/auth/poll?state=" + encodeURIComponent(state))
        .then(function (r) { return r.json(); })
        .then(function (d) {
          if (!d.ready) return;
          stopAuthPoll();
          fetch(basePath + "oauth/finish?code=" + encodeURIComponent(d.exchange_code))
            .then(function (r) { return r.json(); })
            .then(function (fd) {
              if (fd.ok) {
                _loggedIn = true;
                window.LOGGED_IN = true;
                refreshAuth();
                schedTunnel(true);
              } else {
                showAuthError(fd.error || "Sign-in failed");
              }
            })
            .catch(function () { showAuthError("Network error during sign-in"); });
        })
        .catch(function () {});
    }, 2000);
  }

  function openLogin() {
    stopAuthPoll();
    fetch(basePath + "api/auth/begin")
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (!d.ok || !d.state || !d.auth_url) {
          showAuthError(d.error || "Failed to start sign-in");
          return;
        }
        window.open(d.auth_url, "_blank");
        startAuthPoll(d.state, Date.now() + 300000);
      })
      .catch(function () { showAuthError("Failed to start sign-in"); });
  }

  var loginBtn = document.getElementById("auth-login");
  if (loginBtn) {
    loginBtn.addEventListener("click", function (e) {
      e.preventDefault();
      openLogin();
    });
  }

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

  var _tunnelTimer = null;

  function schedTunnel(fast) {
    if (_tunnelTimer) clearTimeout(_tunnelTimer);
    _tunnelTimer = setTimeout(refreshTunnel, fast ? 3000 : POLL_MS);
  }

  function refreshTunnel() {
    var card = document.getElementById("tunnel-card");
    if (!card) { schedTunnel(false); return; }
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
        setText("tunnel-uid", d.unique_id || "\u2014");
        if (d.mode) _tunnelMode = d.mode;
        if (d.mode === "quick") {
          var qRow = document.getElementById("tunnel-quick-url-row");
          var urlEl = document.getElementById("tunnel-url");
          if (d.url) {
            if (urlEl) { urlEl.textContent = d.url; urlEl.href = d.url; }
            if (qRow) qRow.style.display = "";
          } else {
            if (qRow) qRow.style.display = "none";
          }
        } else if (d.mode === "static") {
          setText("tunnel-hostname", d.hostname || "\u2014");
          var sUrlEl = document.getElementById("tunnel-static-url");
          if (sUrlEl && d.url) { sUrlEl.textContent = d.url; sUrlEl.href = d.url; }
        }
        var fbRow = document.getElementById("tunnel-fallback-row");
        var fbEl = document.getElementById("tunnel-fallback-url");
        if (fbRow && fbEl) {
          if (d.fallback_url) {
            fbEl.textContent = d.fallback_url;
            fbEl.href = d.fallback_url;
            fbRow.style.display = "";
          } else {
            fbRow.style.display = "none";
          }
        }
        card.className = "tunnel-card tunnel-card--" + (d.healthy ? "ok" : (d.running ? "warn" : "err"));
        var hOk = document.getElementById("tunnel-hint-ok");
        var hWarn = document.getElementById("tunnel-hint-warn");
        var hErr = document.getElementById("tunnel-hint-err");
        if (hOk) hOk.style.display = d.healthy ? "" : "none";
        if (hWarn) hWarn.style.display = (!d.healthy && d.running) ? "" : "none";
        if (hErr) hErr.style.display = (!d.healthy && !d.running) ? "" : "none";

        toggleStaticUrl();

        var errEl = document.querySelector("#tunnel-card .tunnel-error");
        if (d.error) {
          if (!errEl) {
            errEl = document.createElement("div");
            errEl.className = "tunnel-error";
            errEl.innerHTML = '<svg width="15" height="15" viewBox="0 0 20 20" fill="none" style="flex-shrink:0;margin-top:.1rem"><path d="M10 2L2 17h16L10 2z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><path d="M10 8v4M10 14v1" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg><span></span>';
            var body = document.querySelector("#tunnel-card .tunnel-card__body");
            if (body) body.appendChild(errEl);
          }
          var sp = errEl.querySelector("span");
          if (sp) sp.textContent = d.error;
        } else if (errEl) {
          errEl.remove();
        }
        schedTunnel(d.running && !d.healthy);
      })
      .catch(function () { schedTunnel(false); });
  }

  function refreshAuth() {
    if (!window.BACKEND_AVAILABLE) return;
    fetch(basePath + "api/auth")
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var wrap = document.getElementById("auth-wrap");
        if (!wrap) return;
        var emailEl = document.getElementById("auth-email");
        var loginEl = document.getElementById("auth-login");
        var logoutEl = document.getElementById("auth-logout");
        _loggedIn = d.logged_in;
        window.LOGGED_IN = d.logged_in;
        if (d.logged_in) {
          if (emailEl) {
            emailEl.textContent = d.email || "Signed in";
            emailEl.title = d.email || "Signed in";
            emailEl.style.display = "";
          }
          if (logoutEl) logoutEl.style.display = "";
          if (loginEl) loginEl.style.display = "none";
        } else {
          if (emailEl) emailEl.style.display = "none";
          if (logoutEl) logoutEl.style.display = "none";
          if (loginEl) loginEl.style.display = "";
        }
        toggleStaticUrl();
      })
      .catch(function () {});
  }

  refreshStatus();
  refreshAccess();
  refreshTunnel();
  refreshAuth();

  setInterval(function () {
    refreshStatus();
    refreshAccess();
  }, POLL_MS);

  setInterval(refreshAuth, 60000);
})();
