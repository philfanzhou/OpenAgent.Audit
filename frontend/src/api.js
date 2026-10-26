import { auth } from "./store.js";

async function request(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (auth.token) headers.Authorization = `Bearer ${auth.token}`;
  const resp = await fetch(path, { ...options, headers });
  if (resp.status === 401) {
    auth.logout();
    throw new ApiError(401, "登录已过期，请重新登录");
  }
  if (!resp.ok) {
    let detail = `请求失败 (${resp.status})`;
    try {
      const body = await resp.json();
      if (body.detail) detail = typeof body.detail === "string" ? body.detail : body.detail.message || detail;
      if (body.message) detail = body.message;
    } catch { /* non-JSON error body */ }
    throw new ApiError(resp.status, detail);
  }
  return resp.json();
}

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function qs(params) {
  const clean = Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== "");
  return clean.length ? "?" + new URLSearchParams(clean).toString() : "";
}

export const api = {
  me: () => request("/v1/me"),
  sessions: (params = {}) => request(`/v1/sessions${qs(params)}`),
  session: (id) => request(`/v1/sessions/${encodeURIComponent(id)}`),
  auditLog: (params = {}) => request(`/v1/audit-log${qs(params)}`),
  restoreRequests: (params = {}) => request(`/v1/restore-requests${qs(params)}`),
  createRestoreRequest: (body) =>
    request("/v1/restore-requests", { method: "POST", body: JSON.stringify(body) }),
  approve: (id, comment) =>
    request(`/v1/restore-requests/${id}/approve`, { method: "POST", body: JSON.stringify({ comment }) }),
  reject: (id, comment) =>
    request(`/v1/restore-requests/${id}/reject`, { method: "POST", body: JSON.stringify({ comment }) }),
  reveal: (id) => request(`/v1/restore-requests/${id}/reveal`, { method: "POST" }),
};
