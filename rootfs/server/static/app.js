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
    if (el) el.style.display = (_tunnelMode === "static") ? "" : "none";
    var qRow = document.getElementById("tunnel-quick-url-row");
    if (qRow && _tunnelMode) qRow.style.display = (_tunnelMode === "quick") ? "" : "none";
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

  function refreshVpn() {
    fetch(basePath + "api/vpn")
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var st = document.getElementById("vpn-status");
        if (st) {
          st.textContent = d.enabled ? "\u2713 Active" : "\u25CB Inactive";
          st.className = "access-status " + (d.enabled ? "access-status--ok" : "access-status--neutral");
        }
        var pc = document.getElementById("vpn-peer-count");
        if (pc) pc.textContent = d.peer_count + " total, " + d.connected_count + " connected";
        var card = document.getElementById("vpn-card");
        if (card) card.className = "vpn-card " + (d.enabled ? "vpn-card--ok" : "vpn-card--off");
      })
      .catch(function () {});
  }

  function refreshVpnPeers() {
    var tbody = document.getElementById("vpn-peers-tbody");
    if (!tbody) return;
    fetch(basePath + "api/vpn/peers")
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var peers = d.peers || [];
        var noPeers = document.getElementById("vpn-no-peers");
        if (peers.length === 0) {
          tbody.innerHTML = "";
          if (noPeers) noPeers.style.display = "";
          return;
        }
        if (noPeers) noPeers.style.display = "none";
        var html = "";
        for (var i = 0; i < peers.length; i++) {
          var p = peers[i];
          var exp = p.expires_at ? p.expires_at.substring(0, 16) : "Never";
          var conn = p.connected;
          html += '<tr id="peer-row-' + p.peer_id + '">' +
            "<td>" + _esc(p.name) + "</td>" +
            '<td class="mono">' + p.vpn_ip + "</td>" +
            "<td><span class=\"dot dot--" + (conn ? "green" : "gray") + "\"></span>" + (conn ? "Connected" : "Idle") + "</td>" +
            '<td class="mono small">' + exp + "</td>" +
            "<td>" +
            '<a href="' + basePath + "api/vpn/peers/" + p.peer_id + '/config?network=lan" class="btn btn--sm" title="LAN config">\u2B07 LAN</a>' +
            '<a href="' + basePath + "api/vpn/peers/" + p.peer_id + '/config?network=remote" class="btn btn--sm" title="Remote config">\u2B07 WAN</a>' +
            '<a href="' + basePath + "api/vpn/peers/" + p.peer_id + '/qr?network=lan" class="btn btn--sm" target="_blank" title="LAN QR">\u25FB</a>' +
            '<button class="btn btn--sm btn--red" onclick="vpnRemovePeer(\'' + p.peer_id + '\')" title="Remove peer">\u2715</button>' +
            "</td></tr>";
        }
        tbody.innerHTML = html;
      })
      .catch(function () {});
  }

  function _esc(s) {
    var d = document.createElement("div");
    d.appendChild(document.createTextNode(s || ""));
    return d.innerHTML;
  }

  window.vpnEnable = function () {
    fetch(basePath + "api/vpn/enable", { method: "POST" })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.ok) location.reload();
        else alert(d.error || "Failed to enable VPN");
      })
      .catch(function () { alert("Network error"); });
  };

  window.vpnDisable = function () {
    if (!confirm("Disable VPN? Active peers will be disconnected.")) return;
    fetch(basePath + "api/vpn/disable", { method: "POST" })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.ok) location.reload();
        else alert(d.error || "Failed to disable VPN");
      })
      .catch(function () { alert("Network error"); });
  };

  window.vpnKill = function () {
    if (!confirm("KILL VPN? This removes ALL peers and shuts down the interface immediately.")) return;
    fetch(basePath + "api/vpn/kill", { method: "POST" })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.ok) location.reload();
        else alert(d.error || "Kill switch failed");
      })
      .catch(function () { alert("Network error"); });
  };

  window.toggleAddPeer = function () {
    var form = document.getElementById("vpn-add-form");
    if (form) form.style.display = form.style.display === "none" ? "" : "none";
  };

  window.vpnAddPeer = function () {
    var name = (document.getElementById("peer-name") || {}).value || "";
    var ttlHours = parseFloat((document.getElementById("peer-ttl") || {}).value || "0");
    var persistent = (document.getElementById("peer-persistent") || {}).checked || false;
    if (!name.trim()) { alert("Peer name is required"); return; }
    var ttl = ttlHours > 0 ? Math.round(ttlHours * 3600) : null;
    var body = { name: name.trim(), persistent: persistent };
    if (ttl) body.ttl = ttl;
    fetch(basePath + "api/vpn/peers", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (!d.ok) { alert(d.error || "Failed to create peer"); return; }
        document.getElementById("vpn-add-form").style.display = "none";
        var result = document.getElementById("vpn-peer-result");
        if (result) result.style.display = "";
        var configEl = document.getElementById("vpn-peer-config-text");
        if (configEl) configEl.textContent = d.config || "";
        var dlLink = document.getElementById("vpn-peer-dl-link");
        if (dlLink && d.peer) dlLink.href = basePath + "api/vpn/peers/" + d.peer.peer_id + "/config?network=lan";
        var qrLink = document.getElementById("vpn-peer-qr-link");
        if (qrLink && d.peer) qrLink.href = basePath + "api/vpn/peers/" + d.peer.peer_id + "/qr?network=lan";
        var remoteDl = document.getElementById("vpn-peer-dl-remote");
        var remoteQr = document.getElementById("vpn-peer-qr-remote");
        var remoteBlock = document.getElementById("vpn-remote-block");
        var remoteConfigEl = document.getElementById("vpn-peer-remote-config-text");
        if (d.remote_config && d.peer) {
          if (remoteBlock) remoteBlock.style.display = "";
          if (remoteConfigEl) remoteConfigEl.textContent = d.remote_config;
          if (remoteDl) remoteDl.href = basePath + "api/vpn/peers/" + d.peer.peer_id + "/config?network=remote";
          if (remoteQr) remoteQr.href = basePath + "api/vpn/peers/" + d.peer.peer_id + "/qr?network=remote";
        } else {
          if (remoteBlock) remoteBlock.style.display = "none";
        }
        if (d.qr_available && d.peer) {
          var qrImg = document.getElementById("vpn-peer-qr-img");
          if (qrImg) qrImg.innerHTML = '<img src="' + basePath + "api/vpn/peers/" + d.peer.peer_id + '/qr?network=lan" alt="QR" style="max-width:200px">';
        }
        refreshVpnPeers();
      })
      .catch(function () { alert("Network error"); });
  };

  window.vpnRemovePeer = function (peerId) {
    if (!confirm("Remove this peer?")) return;
    fetch(basePath + "api/vpn/peers/" + peerId, { method: "DELETE" })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.ok) {
          var row = document.getElementById("peer-row-" + peerId);
          if (row) row.remove();
          refreshVpnPeers();
        } else {
          alert(d.error || "Failed to remove peer");
        }
      })
      .catch(function () { alert("Network error"); });
  };

  window.copyPeerConfig = function () {
    var el = document.getElementById("vpn-peer-config-text");
    if (el) {
      navigator.clipboard.writeText(el.textContent).then(function () {
        alert("Config copied to clipboard");
      }).catch(function () {
        var range = document.createRange();
        range.selectNodeContents(el);
        var sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
      });
    }
  };

  setInterval(function () {
    refreshVpn();
    refreshVpnPeers();
    refreshHub();
  }, POLL_MS);

  function refreshHub() {
    fetch(basePath + "api/hub/status")
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (!d.ok && !d.data) return;
        var s = d.data || d;
        var badge = document.getElementById("hub-status-badge");
        if (badge) {
          if (s.connected) {
            badge.textContent = "\u2713 Connected";
            badge.className = "access-status access-status--ok";
          } else {
            badge.textContent = "\u25CB Off";
            badge.className = "access-status access-status--neutral";
          }
        }
        var card = document.getElementById("hub-card");
        if (card) card.className = "vpn-card " + (s.connected ? "vpn-card--ok" : "vpn-card--off");
        var pc = document.getElementById("hub-peer-count");
        if (pc) pc.textContent = (s.peer_count || 0).toString();
      })
      .catch(function () {});
  }

  function refreshHubPeers() {
    var tbody = document.getElementById("hub-peers-tbody");
    if (!tbody) return;
    fetch(basePath + "api/hub/peers")
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var peers = (d.peers || []).filter(function (p) { return p.role === "client" && p.active !== false; });
        var table = document.getElementById("hub-peers-table");
        var noPeers = document.getElementById("hub-no-peers");
        if (peers.length === 0) {
          tbody.innerHTML = "";
          if (table) table.style.display = "none";
          if (noPeers) noPeers.style.display = "";
          return;
        }
        if (table) table.style.display = "";
        if (noPeers) noPeers.style.display = "none";
        var html = "";
        for (var i = 0; i < peers.length; i++) {
          var p = peers[i];
          html += '<tr id="hub-peer-row-' + p.peer_id + '">' +
            "<td>" + _esc(p.name || p.peer_id) + "</td>" +
            '<td class="mono">' + (p.vpn_ip || "") + "</td>" +
            "<td>" +
            (p.config ? '<a href="' + basePath + "api/hub/peers/" + p.peer_id + '/config" class="btn btn--sm" download>\u2B07 .conf</a>' : "") +
            (p.config ? '<a href="' + basePath + "api/hub/peers/" + p.peer_id + '/qr" class="btn btn--sm" target="_blank" title="QR Code">\u25FB</a>' : "") +
            '<button class="btn btn--sm btn--red" onclick="hubRemovePeer(\'' + p.peer_id + '\')" title="Remove">\u2715</button>' +
            "</td></tr>";
        }
        tbody.innerHTML = html;
      })
      .catch(function () {});
  }

  window.hubEnable = function () {
    var btn = document.getElementById("hub-enable-btn");
    if (btn) { btn.disabled = true; btn.textContent = "Connecting\u2026"; }
    fetch(basePath + "api/hub/enable", { method: "POST" })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.ok) location.reload();
        else { alert(d.error || "Failed to enable remote access"); if (btn) { btn.disabled = false; btn.textContent = "Enable Remote Access"; } }
      })
      .catch(function () { alert("Network error"); if (btn) { btn.disabled = false; btn.textContent = "Enable Remote Access"; } });
  };

  window.hubDisable = function () {
    if (!confirm("Disable remote access? Connected devices will be disconnected.")) return;
    fetch(basePath + "api/hub/disable", { method: "POST" })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.ok) location.reload();
        else alert(d.error || "Disconnect failed");
      })
      .catch(function () { alert("Network error"); });
  };

  window.toggleHubAddPeer = function () {
    var form = document.getElementById("hub-add-form");
    if (form) form.style.display = form.style.display === "none" ? "" : "none";
  };

  window.hubAddPeer = function () {
    var name = (document.getElementById("hub-peer-name") || {}).value || "";
    if (!name.trim()) { alert("Device name is required"); return; }
    var btn = document.getElementById("hub-add-peer-btn");
    if (btn) btn.disabled = true;
    fetch(basePath + "api/hub/peers", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: name.trim() }),
    })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (btn) btn.disabled = false;
        if (!d.ok) { alert(d.error || "Failed to add device"); return; }
        document.getElementById("hub-add-form").style.display = "none";
        var result = document.getElementById("hub-peer-result");
        if (result) result.style.display = "";
        var configEl = document.getElementById("hub-peer-config-text");
        if (configEl) configEl.textContent = d.config || "";
        var dlLink = document.getElementById("hub-peer-dl-link");
        if (dlLink && d.peer) {
          dlLink.href = basePath + "api/hub/peers/" + d.peer.peer_id + "/config";
          dlLink.download = "vipsy-remote-" + d.peer.peer_id + ".conf";
        }
        var qrLink = document.getElementById("hub-peer-qr-link");
        if (qrLink && d.peer) {
          qrLink.href = basePath + "api/hub/peers/" + d.peer.peer_id + "/qr";
        }
        var qrImg = document.getElementById("hub-peer-qr-img");
        if (qrImg && d.peer) {
          qrImg.innerHTML = '<img src="' + basePath + "api/hub/peers/" + d.peer.peer_id + '/qr" alt="QR" style="max-width:220px;margin-top:.5rem">';
        }
        refreshHubPeers();
      })
      .catch(function () { if (btn) btn.disabled = false; alert("Network error"); });
  };

  window.hubRemovePeer = function (peerId) {
    if (!confirm("Remove this hub peer?")) return;
    fetch(basePath + "api/hub/peers/" + peerId, { method: "DELETE" })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.ok) {
          var row = document.getElementById("hub-peer-row-" + peerId);
          if (row) row.remove();
          refreshHubPeers();
        } else {
          alert(d.error || "Failed to remove hub peer");
        }
      })
      .catch(function () { alert("Network error"); });
  };

  window.copyHubPeerConfig = function () {
    var el = document.getElementById("hub-peer-config-text");
    if (el) {
      navigator.clipboard.writeText(el.textContent).then(function () {
        alert("Config copied to clipboard");
      }).catch(function () {
        var range = document.createRange();
        range.selectNodeContents(el);
        var sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
      });
    }
  };

  refreshHub();
  refreshHubPeers();
})();
