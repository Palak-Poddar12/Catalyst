export const DEMO_ACCOUNTS = {
  ADMIN: { id: "USR-001", name: "SatGuard Administrator", email: "admin@satguard.local", password: "admin123", role: "ADMIN" },
  ANALYST: { id: "USR-002", name: "SOC Analyst", email: "analyst@satguard.local", password: "analyst123", role: "ANALYST" },
  INVESTIGATOR: { id: "USR-003", name: "Forensic Investigator", email: "investigator@satguard.local", password: "invest123", role: "INVESTIGATOR" },
  VIEWER: { id: "USR-004", name: "Security Viewer", email: "viewer@satguard.local", password: "viewer123", role: "VIEWER" }
};

const SESSION_KEY = "satguard_session";
const TOKEN_KEY = "satguard_token";
const REMEMBER_KEY = "satguard_remembered_login";

export function authenticateLocal(email, password) {
  const account = Object.values(DEMO_ACCOUNTS).find(
    (user) => user.email.toLowerCase() === String(email).trim().toLowerCase() && user.password === password
  );

  if (!account) return null;

  return {
    authenticated: true,
    access_token: `satguard-local-${account.role.toLowerCase()}`,
    token_type: "bearer",
    user: {
      id: account.id,
      name: account.name,
      email: account.email,
      role: account.role
    }
  };
}

export function getSession() {
  try {
    return JSON.parse(localStorage.getItem(SESSION_KEY) || sessionStorage.getItem(SESSION_KEY) || "null");
  } catch {
    return null;
  }
}

export function saveSession(session, remember = true) {
  const storage = remember ? localStorage : sessionStorage;
  const other = remember ? sessionStorage : localStorage;
  other.removeItem(SESSION_KEY);
  storage.setItem(SESSION_KEY, JSON.stringify(session));
  const token = session?.access_token || session?.token;
  if (token) {
    other.removeItem(TOKEN_KEY);
    storage.setItem(TOKEN_KEY, token);
  }
}

export function saveRememberedLogin(email, password) {
  localStorage.setItem(REMEMBER_KEY, JSON.stringify({ email, password }));
}

export function getRememberedLogin() {
  try {
    return JSON.parse(localStorage.getItem(REMEMBER_KEY) || "null");
  } catch {
    return null;
  }
}

export function clearRememberedLogin() {
  localStorage.removeItem(REMEMBER_KEY);
}

export function clearSession() {
  localStorage.removeItem(SESSION_KEY);
  sessionStorage.removeItem(SESSION_KEY);
  localStorage.removeItem(TOKEN_KEY);
  sessionStorage.removeItem(TOKEN_KEY);
}

export function getToken() {
  return localStorage.getItem(TOKEN_KEY) || sessionStorage.getItem(TOKEN_KEY);
}

export function roleOf(session) {
  return String(session?.user?.role || session?.role || "VIEWER").toUpperCase();
}
