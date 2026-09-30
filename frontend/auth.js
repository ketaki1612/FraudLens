/*
 * Shared auth/session handling, included by every page except login.html.
 *
 * Session (token + user info) is stored in sessionStorage - it clears
 * automatically when the browser tab closes, unlike localStorage.
 */

const API_BASE = "http://127.0.0.1:8000";

// Which pages each role is allowed to see in the sidebar.
// Auditor sees everything (read-only enforced by hiding edit controls
// on each page individually, not by hiding pages).
const SIDEBAR_LINKS = [
  { href: "index.html",         icon: "bi-grid-1x2",     label: "Dashboard",    roles: ["Admin", "Analyst", "Auditor"] },
  { href: "transactions.html",  icon: "bi-list-ul",      label: "Transactions", roles: ["Admin", "Analyst", "Auditor"] },
  { href: "fraud-rules.html",   icon: "bi-shield-check", label: "Fraud Rules",  roles: ["Admin", "Analyst", "Auditor"] },
  { href: "audit-logs.html",    icon: "bi-bar-chart",    label: "Audit Logs",   roles: ["Admin", "Auditor"] },
  { href: "settings.html",      icon: "bi-gear",         label: "Settings",     roles: ["Admin"] },
  { href: "register.html",      icon: "bi-person-plus",  label: "Register User", roles: ["Admin"] },
  { href: "mfa-setup.html",     icon: "bi-shield-lock",  label: "Set Up MFA",    roles: ["Admin", "Analyst", "Auditor"] },
];

function getSession() {
  const raw = sessionStorage.getItem("session");
  return raw ? JSON.parse(raw) : null;
}

function saveSession(tokenResponse) {
  sessionStorage.setItem("session", JSON.stringify(tokenResponse));
  updateLastActivity();
}

function logout() {
  sessionStorage.removeItem("session");
  sessionStorage.removeItem("lastActivity");
  window.location.href = "login.html";
}

// --- Idle timeout (PCI DSS-style: end the session after inactivity) ---
const IDLE_TIMEOUT_MINUTES = 15;

function updateLastActivity() {
  sessionStorage.setItem("lastActivity", Date.now().toString());
}

function checkIdleTimeout() {
  const last = sessionStorage.getItem("lastActivity");
  if (last && Date.now() - parseInt(last, 10) > IDLE_TIMEOUT_MINUTES * 60 * 1000) {
    alert("You've been logged out due to inactivity.");
    logout();
    return true;
  }
  return false;
}

// Any click or keypress resets the idle clock.
["click", "keydown"].forEach(evt => document.addEventListener(evt, updateLastActivity));

// --- bfcache fix: force a fresh reload if the page was restored from
// the browser's back/forward cache, so requireAuth() actually re-runs
// against the CURRENT session state instead of a frozen snapshot.
window.addEventListener("pageshow", (event) => {
  if (event.persisted) {
    window.location.reload();
  }
});

/**
 * Wrapper around fetch() for API calls: attaches the auth header, and
 * if the server ever responds 401/403 (expired token, no token, wrong
 * role), clears the session and bounces to login instead of leaving
 * the page stuck showing a generic error.
 */
async function apiFetch(url, options = {}) {
  const res = await fetch(url, {
    ...options,
    headers: { ...(options.headers || {}), ...authHeaders() },
  });
  if (res.status === 401 || res.status === 403) {
    logout();
    throw new Error("Session expired - redirecting to login.");
  }
  return res;
}

/**
 * Call at the top of every protected page. Redirects to login.html if
 * there's no session, and blocks access to pages this role can't see
 * (e.g. an Analyst directly typing settings.html in the URL bar).
 */
function requireAuth(currentPage) {
  const session = getSession();
  if (!session) {
    window.location.href = "login.html";
    return null;
  }

  if (checkIdleTimeout()) {
    return null; // checkIdleTimeout already redirected to login
  }
  updateLastActivity();

  const role = session.user.role_name;
  const allowedPages = SIDEBAR_LINKS.filter(l => l.roles.includes(role)).map(l => l.href);
  if (!allowedPages.includes(currentPage)) {
    alert("You don't have access to that page.");
    window.location.href = "index.html";
    return null;
  }

  // Re-check idle timeout every 30 seconds while this page is open,
  // so a session doesn't just silently expire only on next navigation.
  setInterval(checkIdleTimeout, 30 * 1000);

  return session;
}

/** Returns headers with the Authorization bearer token attached. */
function authHeaders() {
  const session = getSession();
  return session ? { "Authorization": `Bearer ${session.access_token}` } : {};
}

/** Renders the sidebar links this role is allowed to see, marking the active page. */
function renderSidebar(currentPage, role) {
  const container = document.getElementById("sidebarNav");
  if (!container) return;
  container.innerHTML = SIDEBAR_LINKS
    .filter(link => link.roles.includes(role))
    .map(link => `
      <a href="${link.href}" class="nav-link ${link.href === currentPage ? 'active' : ''}">
        <i class="bi ${link.icon}"></i> ${link.label}
      </a>
    `).join("");
}