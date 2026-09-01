<<<<<<< HEAD
// Author: Avinash Krishna — Team AVV Elites (SIH26153)
=======
>>>>>>> 77949f2bb89fea05df3ee4faf24abd4771ef1671
// platform/frontend/static/js/app.js
//
// Token storage note (see SECURITY.md "known trade-offs"): access + refresh
// tokens are kept in localStorage, standard for a Bearer-token JSON API.
// Access tokens are deliberately short-lived (15 min, see config.py) to
// bound the exposure window if this were ever read via an XSS bug; the CSP
// in app/middleware.py (script-src 'self', no inline scripts, no third-
// party origins at all) is the primary control preventing that XSS in the
// first place. A team wanting defense-in-depth beyond CSP can migrate the
// refresh token to an httpOnly cookie — see SECURITY.md for that upgrade
// path; it's a deliberate scope cut here, not an oversight.

const API_BASE = "/api";

function getTokens() {
  return {
    access: localStorage.getItem("nexusai_access_token"),
    refresh: localStorage.getItem("nexusai_refresh_token"),
  };
}
function setTokens(access, refresh) {
  localStorage.setItem("nexusai_access_token", access);
  if (refresh) localStorage.setItem("nexusai_refresh_token", refresh);
}
function clearTokens() {
  localStorage.removeItem("nexusai_access_token");
  localStorage.removeItem("nexusai_refresh_token");
}

async function apiFetch(path, options = {}, _retried = false) {
  const { access } = getTokens();
  const headers = Object.assign({}, options.headers || {});
  if (access) headers["Authorization"] = `Bearer ${access}`;
  if (options.body && !(options.body instanceof FormData) && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }

  const response = await fetch(API_BASE + path, Object.assign({}, options, { headers }));

  if (response.status === 401 && !_retried) {
    const refreshed = await tryRefresh();
    if (refreshed) return apiFetch(path, options, true);
    clearTokens();
    window.location.href = "/";
    return response;
  }
  return response;
}

async function tryRefresh() {
  const { refresh } = getTokens();
  if (!refresh) return false;
  try {
    const res = await fetch(API_BASE + "/auth/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refresh }),
    });
    if (!res.ok) return false;
    const data = await res.json();
    setTokens(data.access_token, data.refresh_token);
    return true;
  } catch {
    return false;
  }
}

function showAlert(el, message, type = "error") {
  el.textContent = message;
  el.className = `alert alert-${type} visible`;
}

function requireAuth() {
  const { access } = getTokens();
  if (!access) {
    window.location.href = "/";
  }
}

async function logout() {
  const { refresh } = getTokens();
  try {
    await apiFetch("/auth/logout", { method: "POST", body: JSON.stringify({ refresh_token: refresh }) });
  } catch { /* best-effort — clear local state regardless */ }
  clearTokens();
  window.location.href = "/";
}

// ---------------------------------------------------------------------
// Page: login
// ---------------------------------------------------------------------
function initLoginPage() {
  const form = document.getElementById("login-form");
  if (!form) return;
  const alertEl = document.getElementById("login-alert");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    alertEl.classList.remove("visible");
    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value;

    const res = await fetch(API_BASE + "/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      showAlert(alertEl, data.detail || "Could not sign in. Please check your details and try again.");
      return;
    }
    setTokens(data.access_token, data.refresh_token);
    window.location.href = "/dashboard";
  });
}

// ---------------------------------------------------------------------
// Page: register
// ---------------------------------------------------------------------
function initRegisterPage() {
  const form = document.getElementById("register-form");
  if (!form) return;
  const alertEl = document.getElementById("register-alert");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    alertEl.classList.remove("visible");
    const payload = {
      email: document.getElementById("email").value.trim(),
      password: document.getElementById("password").value,
      full_name: document.getElementById("full_name").value.trim(),
      organization_name: document.getElementById("organization_name").value.trim(),
    };
    const res = await fetch(API_BASE + "/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      const msg = Array.isArray(data.detail) ? data.detail.map(d => d.msg).join(" ") : (data.detail || "Registration failed.");
      showAlert(alertEl, msg);
      return;
    }
    showAlert(alertEl, "Account created. Check the server console log for your verification link (demo mode has no real mail server).", "success");
    form.reset();
  });
}

// ---------------------------------------------------------------------
// Page: dashboard
// ---------------------------------------------------------------------
async function initDashboardPage() {
  const root = document.getElementById("dashboard-root");
  if (!root) return;
  requireAuth();

  const me = await (await apiFetch("/auth/me")).json();
  document.getElementById("user-name").textContent = me.full_name;

  const segSelect = document.getElementById("segment-select");
  const segmentsRes = await apiFetch("/segments");
  const segments = await segmentsRes.json();

  if (segments.length === 0) {
    document.getElementById("no-segments-state").classList.remove("hidden");
  } else {
    segments.forEach(s => {
      const opt = document.createElement("option");
      opt.value = s.id; opt.textContent = s.name;
      segSelect.appendChild(opt);
    });
    await loadForecasts(segments[0].id);
  }

  segSelect.addEventListener("change", () => loadForecasts(segSelect.value));

  document.getElementById("create-segment-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const name = document.getElementById("segment-name").value.trim();
    const res = await apiFetch("/segments", { method: "POST", body: JSON.stringify({ name }) });
    if (res.ok) window.location.reload();
  });

  document.getElementById("demo-forecast-btn")?.addEventListener("click", async () => {
    const segmentId = segSelect.value;
    if (!segmentId) return;
    const btn = document.getElementById("demo-forecast-btn");
    btn.disabled = true; btn.textContent = "Running inference…";
    const res = await apiFetch(`/segments/${segmentId}/forecasts/demo-sample`, { method: "POST" });
    btn.disabled = false; btn.textContent = "Run demo forecast";
    if (res.ok) {
      await loadForecasts(segmentId);
    } else {
      const data = await res.json().catch(() => ({}));
      alert(data.detail || "Could not run forecast.");
    }
  });
}

async function loadForecasts(segmentId) {
  const tbody = document.getElementById("forecasts-tbody");
  tbody.innerHTML = `<tr><td colspan="5">Loading…</td></tr>`;
  const res = await apiFetch(`/forecasts?segment_id=${encodeURIComponent(segmentId)}`);
  const forecasts = await res.json();

  if (forecasts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty-state">No forecasts yet for this segment.</td></tr>`;
    return;
  }
  tbody.innerHTML = "";
  forecasts.forEach(f => {
    const tr = document.createElement("tr");
    const stageClass = {
      "Reconnaissance": "badge-recon", "Initial Access": "badge-access",
      "Lateral Movement": "badge-lateral", "Command and Control": "badge-c2", "Exfiltration": "badge-exfil",
    }[f.predicted_stage] || "badge-recon";
    const maxProb = Math.max(...Object.values(f.infiltration_probabilities));
    tr.innerHTML = `
      <td class="mono">${escapeHtml(f.host_identifier)}</td>
      <td><span class="badge ${stageClass}">${escapeHtml(f.predicted_stage)}</span></td>
      <td class="mono">${(maxProb * 100).toFixed(0)}%</td>
      <td>${f.cross_validated === true ? '<span class="badge badge-verified">cross-validated</span>' : "—"}</td>
      <td><a href="/copilot?forecast_id=${encodeURIComponent(f.id)}">View explanation →</a></td>
    `;
    tbody.appendChild(tr);
  });
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

// ---------------------------------------------------------------------
// Page: copilot
// ---------------------------------------------------------------------
async function initCopilotPage() {
  const root = document.getElementById("copilot-root");
  if (!root) return;
  requireAuth();

  const params = new URLSearchParams(window.location.search);
  const forecastId = params.get("forecast_id");
  if (!forecastId) {
    document.getElementById("copilot-empty").classList.remove("hidden");
    return;
  }

  const res = await apiFetch("/copilot/explain", {
    method: "POST",
    body: JSON.stringify({ forecast_id: forecastId }),
  });
  if (!res.ok) {
    document.getElementById("copilot-empty").classList.remove("hidden");
    return;
  }
  const data = await res.json();

  document.getElementById("copilot-headline").textContent = data.headline;

  const evidenceEl = document.getElementById("copilot-evidence");
  evidenceEl.innerHTML = "";
  data.evidence_bullets.forEach(b => {
    const li = document.createElement("li"); li.textContent = b; evidenceEl.appendChild(li);
  });

  const techniquesEl = document.getElementById("copilot-techniques");
  techniquesEl.innerHTML = "";
  data.retrieved_techniques.forEach(t => {
    const div = document.createElement("div");
    div.className = "technique-card";
    div.innerHTML = `<div class="tid">${escapeHtml(t.id)} · relevance ${t.relevance_score}</div>
                      <div class="tname">${escapeHtml(t.name)}</div>
                      <p>${escapeHtml(t.network_signature)}</p>`;
    techniquesEl.appendChild(div);
  });

  const actionsEl = document.getElementById("copilot-actions");
  actionsEl.innerHTML = "";
  data.recommended_actions.forEach(a => {
    const li = document.createElement("li"); li.textContent = a; actionsEl.appendChild(li);
  });

  const narrationPanel = document.getElementById("copilot-narration-panel");
  if (data.llm_narration) {
    narrationPanel.classList.remove("hidden");
    document.getElementById("copilot-narration").textContent = data.llm_narration;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initLoginPage();
  initRegisterPage();
  initDashboardPage();
  initCopilotPage();
  document.querySelectorAll("[data-action='logout']").forEach(btn => btn.addEventListener("click", logout));
});
