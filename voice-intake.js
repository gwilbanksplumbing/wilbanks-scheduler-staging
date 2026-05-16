/* Wilbanks Voice Intake — phase 1 (staging)
 * Gated by localStorage.wc_voice === "1". Adds a mic button to the New Appointment page,
 * transcribes via Web Speech API, sends transcript to /api/voice/parse-appointment,
 * and pre-fills the form. Never auto-submits. Form testids the script writes to:
 *   input-customer-name, input-customer-phone, input-customer-email, input-job-address,
 *   input-scheduled-date, input-scheduled-time, select-service-type, select-tech-name,
 *   textarea-notes
 */
(function () {
  "use strict";

  // ── Gate ────────────────────────────────────────────────────────────────────
  try {
    if (localStorage.getItem("wc_voice") !== "1") return;
  } catch (e) { return; }

  // ── Config ──────────────────────────────────────────────────────────────────
  var API_BASE = "https://wilbanks-server-staging.up.railway.app";
  var ENDPOINT = API_BASE + "/api/voice/parse-appointment";
  var TOKEN_KEYS = ["wc_auth_token", "authToken", "wc_token"];

  function getToken() {
    for (var i = 0; i < TOKEN_KEYS.length; i++) {
      try { var t = localStorage.getItem(TOKEN_KEYS[i]); if (t) return t; } catch (e) {}
    }
    return "";
  }

  // ── DOM helpers ─────────────────────────────────────────────────────────────
  function byTid(tid) { return document.querySelector('[data-testid="' + tid + '"]'); }

  // React-friendly input setter (works with controlled inputs)
  function setInputValue(el, value) {
    if (!el) return false;
    var proto = el.tagName === "TEXTAREA"
      ? window.HTMLTextAreaElement.prototype
      : (el.tagName === "SELECT" ? window.HTMLSelectElement.prototype : window.HTMLInputElement.prototype);
    var setter = Object.getOwnPropertyDescriptor(proto, "value");
    if (setter && setter.set) setter.set.call(el, value); else el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    return true;
  }

  function setByTid(tid, value) {
    var el = byTid(tid);
    if (!el || value == null || value === "") return false;
    return setInputValue(el, String(value));
  }

  // ── UI: mic button + status pill ────────────────────────────────────────────
  function injectStyles() {
    if (document.getElementById("wc-voice-styles")) return;
    var s = document.createElement("style");
    s.id = "wc-voice-styles";
    s.textContent =
      ".wc-voice-fab{position:fixed;bottom:max(20px,env(safe-area-inset-bottom));right:20px;z-index:9999;" +
      "width:64px;height:64px;border-radius:50%;background:#2563eb;color:#fff;border:none;" +
      "box-shadow:0 6px 20px rgba(0,0,0,.3);display:flex;align-items:center;justify-content:center;" +
      "cursor:pointer;font-size:28px;-webkit-tap-highlight-color:transparent}" +
      ".wc-voice-fab:active{transform:scale(.96)}" +
      ".wc-voice-fab.rec{background:#dc2626;animation:wcpulse 1.2s ease-in-out infinite}" +
      "@keyframes wcpulse{0%,100%{box-shadow:0 6px 20px rgba(220,38,38,.5)}50%{box-shadow:0 0 0 16px rgba(220,38,38,0)}}" +
      ".wc-voice-pill{position:fixed;bottom:max(96px,calc(env(safe-area-inset-bottom) + 76px));right:20px;z-index:9999;" +
      "max-width:min(80vw,360px);background:#0f172a;color:#fff;padding:10px 14px;border-radius:12px;" +
      "font:13px -apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;box-shadow:0 6px 20px rgba(0,0,0,.3);" +
      "opacity:0;transform:translateY(8px);transition:opacity .2s,transform .2s;pointer-events:none}" +
      ".wc-voice-pill.show{opacity:1;transform:translateY(0)}" +
      ".wc-voice-pill .err{color:#fca5a5}" +
      ".wc-voice-pill .ok{color:#86efac}";
    document.head.appendChild(s);
  }

  function ensureFab() {
    var fab = document.getElementById("wc-voice-fab");
    if (fab) return fab;
    fab = document.createElement("button");
    fab.id = "wc-voice-fab";
    fab.className = "wc-voice-fab";
    fab.setAttribute("aria-label", "Voice intake");
    fab.setAttribute("title", "Voice intake");
    fab.textContent = "🎤";
    fab.addEventListener("click", onMicTap);
    document.body.appendChild(fab);
    return fab;
  }

  function removeFab() {
    var fab = document.getElementById("wc-voice-fab");
    if (fab) fab.remove();
    var pill = document.getElementById("wc-voice-pill");
    if (pill) pill.remove();
  }

  function showStatus(html, kind) {
    var pill = document.getElementById("wc-voice-pill");
    if (!pill) {
      pill = document.createElement("div");
      pill.id = "wc-voice-pill";
      pill.className = "wc-voice-pill";
      document.body.appendChild(pill);
    }
    pill.innerHTML = kind === "err" ? ('<span class="err">' + html + "</span>")
      : kind === "ok" ? ('<span class="ok">' + html + "</span>")
      : html;
    requestAnimationFrame(function () { pill.classList.add("show"); });
    clearTimeout(showStatus._t);
    showStatus._t = setTimeout(function () { pill.classList.remove("show"); }, 4500);
  }

  // ── Route detection: only show FAB on /new ──────────────────────────────────
  function isOnNewAppointment() {
    var h = window.location.hash || "";
    return /^#\/new(\?|$)/.test(h);
  }

  function syncFabVisibility() {
    if (isOnNewAppointment()) ensureFab(); else removeFab();
  }

  // ── Speech recognition ──────────────────────────────────────────────────────
  var SpeechRec = window.SpeechRecognition || window.webkitSpeechRecognition;
  var recognizing = false;
  var rec = null;

  function startRec() {
    if (!SpeechRec) {
      showStatus("Voice not supported on this browser. Use Safari on iOS.", "err");
      return;
    }
    if (recognizing) { stopRec(); return; }
    rec = new SpeechRec();
    rec.lang = "en-US";
    rec.interimResults = true;
    rec.continuous = false;
    rec.maxAlternatives = 1;

    var finalText = "";
    rec.onresult = function (ev) {
      var interim = "";
      for (var i = ev.resultIndex; i < ev.results.length; i++) {
        var r = ev.results[i];
        if (r.isFinal) finalText += r[0].transcript; else interim += r[0].transcript;
      }
      showStatus("Listening: " + (finalText || interim || "...").slice(0, 80));
    };
    rec.onerror = function (ev) {
      recognizing = false;
      var fab = document.getElementById("wc-voice-fab");
      if (fab) fab.classList.remove("rec");
      showStatus("Mic error: " + (ev.error || "unknown"), "err");
    };
    rec.onend = function () {
      recognizing = false;
      var fab = document.getElementById("wc-voice-fab");
      if (fab) fab.classList.remove("rec");
      var transcript = (finalText || "").trim();
      if (!transcript) { showStatus("No speech detected.", "err"); return; }
      sendTranscript(transcript);
    };

    try {
      rec.start();
      recognizing = true;
      var fab = document.getElementById("wc-voice-fab");
      if (fab) fab.classList.add("rec");
      showStatus("Listening… tap mic again to stop.");
    } catch (e) {
      showStatus("Could not start mic: " + e.message, "err");
    }
  }

  function stopRec() { if (rec && recognizing) { try { rec.stop(); } catch (e) {} } }

  function onMicTap() {
    if (recognizing) stopRec(); else startRec();
  }

  // ── Send transcript to server, then prefill ─────────────────────────────────
  function sendTranscript(transcript) {
    showStatus("Parsing: " + transcript.slice(0, 60) + "…");
    var today = new Date().toISOString().slice(0, 10);

    fetch(ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + getToken(),
      },
      body: JSON.stringify({ transcript: transcript, today: today }),
    })
      .then(function (r) {
        if (!r.ok) return r.text().then(function (t) { throw new Error("HTTP " + r.status + ": " + t.slice(0, 120)); });
        return r.json();
      })
      .then(function (data) { applyFields(data, transcript); })
      .catch(function (err) { showStatus("Parse failed: " + err.message, "err"); });
  }

  // Try to set a Radix combobox by clicking trigger + matching option. Returns Promise<boolean>.
  function setRadixCombobox(triggerEl, label) {
    return new Promise(function (resolve) {
      if (!triggerEl || !label) { resolve(false); return; }
      try { triggerEl.click(); } catch (e) { resolve(false); return; }
      // Radix renders options in a portal after a tick
      setTimeout(function () {
        var opts = document.querySelectorAll('[role="option"]');
        var match = null;
        for (var i = 0; i < opts.length; i++) {
          var txt = (opts[i].textContent || "").trim().toLowerCase();
          if (txt === String(label).toLowerCase() || txt.indexOf(String(label).toLowerCase()) === 0) { match = opts[i]; break; }
        }
        if (match) { match.click(); resolve(true); }
        else {
          // Close the popover by clicking elsewhere
          try { document.body.click(); } catch (e) {}
          resolve(false);
        }
      }, 120);
    });
  }

  function applyFields(data, transcript) {
    if (!data) { showStatus("Empty response", "err"); return; }

    if (data.intent === "lookup_availability") {
      var d = data.availabilityDate ? (" for " + data.availabilityDate) : "";
      showStatus("Availability lookup requested" + d + " — not implemented yet (phase 2).", "err");
      return;
    }

    var f = data.fields || {};
    var matched = data.matchedCustomer || null;

    // Compose customerName from firstName + lastName, prefer matched record.
    // Fallback: if Groq only filled lastName, try to recover a first name from the transcript.
    var customerName = "";
    if (matched && matched.name) {
      customerName = matched.name;
    } else {
      var fn = (f.firstName || "").trim();
      var ln = (f.lastName || "").trim();
      if (!fn && ln && transcript) {
        // Look for "<Word> <ln>" in the transcript (capitalized first word before lastName)
        var re = new RegExp("([A-Z][a-z]+)\\s+" + ln.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\$&"), "");
        var m = transcript.match(re);
        if (m) fn = m[1];
      }
      customerName = [fn, ln].filter(Boolean).join(" ").trim();
    }

    var phone = (matched && matched.phone) || f.customerPhone || "";
    var address = (matched && matched.address) || f.jobAddress || "";

    var applied = 0;
    if (setByTid("input-customer-name", customerName)) applied++;
    if (setByTid("input-customer-phone", phone)) applied++;
    if (setByTid("input-customer-email", f.customerEmail)) applied++;
    if (setByTid("input-job-address", address)) applied++;
    if (setByTid("input-scheduled-date", f.scheduledDate)) applied++;
    if (setByTid("input-scheduled-time", f.scheduledTime)) applied++;
    if (setByTid("select-tech-name", f.technicianName)) applied++;
    if (setByTid("textarea-notes", f.notes)) applied++;

    // Service type is a Radix combobox — use click-and-select
    var serviceTrigger = byTid("select-service-type");
    if (serviceTrigger && f.serviceType) {
      setRadixCombobox(serviceTrigger, f.serviceType).then(function (ok) {
        if (ok) applied++;
        finalize();
      });
    } else {
      finalize();
    }

    function finalize() {
      var missing = (data.missing || []).filter(function (m) { return m !== "customerEmail" && m !== "technicianName" && m !== "notes"; });
      var msg = "Filled " + applied + " field" + (applied === 1 ? "" : "s");
      if (matched) msg += " (matched " + matched.name + ")";
      if (missing.length) msg += " — review: " + missing.join(", ");
      showStatus(msg, "ok");
    }
  }

  // ── Boot ────────────────────────────────────────────────────────────────────
  function boot() {
    injectStyles();
    syncFabVisibility();
    window.addEventListener("hashchange", syncFabVisibility);
    // Re-check periodically in case the form mounts after route change
    setInterval(syncFabVisibility, 1500);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
