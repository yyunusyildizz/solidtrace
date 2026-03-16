export type AuthSession = {
  accessToken: string;
  refreshToken?: string | null;
  username?: string | null;
};

const ACCESS_TOKEN_KEY = "solidtrace_access_token";
const REFRESH_TOKEN_KEY = "solidtrace_refresh_token";
const USERNAME_KEY = "solidtrace_username";

function hasWindow() {
  return typeof window !== "undefined";
}

export function getToken(): string | null {
  if (!hasWindow()) return null;
  return window.localStorage.getItem(ACCESS_TOKEN_KEY);
}

export function getRefreshToken(): string | null {
  if (!hasWindow()) return null;
  return window.localStorage.getItem(REFRESH_TOKEN_KEY);
}

export function getUsername(): string | null {
  if (!hasWindow()) return null;
  return window.localStorage.getItem(USERNAME_KEY);
}

export function setAuthSession(session: AuthSession) {
  if (!hasWindow()) return;

  window.localStorage.setItem(ACCESS_TOKEN_KEY, session.accessToken);

  if (session.refreshToken) {
    window.localStorage.setItem(REFRESH_TOKEN_KEY, session.refreshToken);
  } else {
    window.localStorage.removeItem(REFRESH_TOKEN_KEY);
  }

  if (session.username) {
    window.localStorage.setItem(USERNAME_KEY, session.username);
  } else {
    window.localStorage.removeItem(USERNAME_KEY);
  }
}

export function clearAuthSession() {
  if (!hasWindow()) return;

  window.localStorage.removeItem(ACCESS_TOKEN_KEY);
  window.localStorage.removeItem(REFRESH_TOKEN_KEY);
  window.localStorage.removeItem(USERNAME_KEY);
}

export function isAuthenticated() {
  return Boolean(getToken());
}