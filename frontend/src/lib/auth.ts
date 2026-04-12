export type AuthSession = {
  accessToken: string;
  refreshToken?: string | null;
  username?: string | null;
};

const ACCESS_TOKEN_KEY = "solidtrace_access_token";
const REFRESH_TOKEN_KEY = "solidtrace_refresh_token";
const USERNAME_KEY = "solidtrace_username";

const ACCESS_TOKEN_COOKIE = "st_access_token";
const REFRESH_TOKEN_COOKIE = "st_refresh_token";
const USERNAME_COOKIE = "st_username";

function hasWindow() {
  return typeof window !== "undefined";
}

function setCookie(name: string, value: string, maxAgeSeconds: number) {
  if (!hasWindow()) return;
  document.cookie = `${name}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAgeSeconds}; SameSite=Lax`;
}

function clearCookie(name: string) {
  if (!hasWindow()) return;
  document.cookie = `${name}=; Path=/; Max-Age=0; SameSite=Lax`;
}

function getCookie(name: string): string | null {
  if (!hasWindow()) return null;
  const cookie = document.cookie
    .split("; ")
    .find((row) => row.startsWith(`${name}=`));
  if (!cookie) return null;
  const value = cookie.split("=").slice(1).join("=");
  return value ? decodeURIComponent(value) : null;
}

function syncCookieFromLocalStorage(localKey: string, cookieKey: string, maxAgeSeconds: number) {
  if (!hasWindow()) return null;

  const localValue = window.localStorage.getItem(localKey);
  if (localValue) {
    setCookie(cookieKey, localValue, maxAgeSeconds);
    return localValue;
  }

  const cookieValue = getCookie(cookieKey);
  if (cookieValue) {
    window.localStorage.setItem(localKey, cookieValue);
    return cookieValue;
  }

  return null;
}

export function getToken(): string | null {
  if (!hasWindow()) return null;
  return syncCookieFromLocalStorage(ACCESS_TOKEN_KEY, ACCESS_TOKEN_COOKIE, 60 * 60 * 24);
}

export function getRefreshToken(): string | null {
  if (!hasWindow()) return null;
  return syncCookieFromLocalStorage(REFRESH_TOKEN_KEY, REFRESH_TOKEN_COOKIE, 60 * 60 * 24 * 30);
}

export function getUsername(): string | null {
  if (!hasWindow()) return null;
  return syncCookieFromLocalStorage(USERNAME_KEY, USERNAME_COOKIE, 60 * 60 * 24 * 30);
}

export function setAuthSession(session: AuthSession) {
  if (!hasWindow()) return;

  window.localStorage.setItem(ACCESS_TOKEN_KEY, session.accessToken);
  setCookie(ACCESS_TOKEN_COOKIE, session.accessToken, 60 * 60 * 24);

  if (session.refreshToken) {
    window.localStorage.setItem(REFRESH_TOKEN_KEY, session.refreshToken);
    setCookie(REFRESH_TOKEN_COOKIE, session.refreshToken, 60 * 60 * 24 * 30);
  } else {
    window.localStorage.removeItem(REFRESH_TOKEN_KEY);
    clearCookie(REFRESH_TOKEN_COOKIE);
  }

  if (session.username) {
    window.localStorage.setItem(USERNAME_KEY, session.username);
    setCookie(USERNAME_COOKIE, session.username, 60 * 60 * 24 * 30);
  } else {
    window.localStorage.removeItem(USERNAME_KEY);
    clearCookie(USERNAME_COOKIE);
  }
}

export function clearAuthSession() {
  if (!hasWindow()) return;

  window.localStorage.removeItem(ACCESS_TOKEN_KEY);
  window.localStorage.removeItem(REFRESH_TOKEN_KEY);
  window.localStorage.removeItem(USERNAME_KEY);

  clearCookie(ACCESS_TOKEN_COOKIE);
  clearCookie(REFRESH_TOKEN_COOKIE);
  clearCookie(USERNAME_COOKIE);
}

export function isAuthenticated() {
  return Boolean(getToken());
}

export function getAuthCookieNames() {
  return {
    access: ACCESS_TOKEN_COOKIE,
    refresh: REFRESH_TOKEN_COOKIE,
    username: USERNAME_COOKIE,
  };
}
