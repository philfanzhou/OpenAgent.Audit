// audit-api JSON 封装：同源 Cookie 会话，401 时跳转登录页。
export class ApiError extends Error {
  constructor(status, detail) {
    super(detail || `请求失败（${status}）`)
    this.status = status
  }
}

// 登录类接口自己处理 401（密码错误等），不触发跳转。
const LOGIN_URL = /\/login/

async function request(url, options = {}) {
  const resp = await fetch(url, {
    credentials: 'same-origin',
    ...options
  })
  // 会话已失效（登录态到期，或服务端重启清空了内存会话）：整页回到登录页，
  // 登录后回到当前页。这里故意不 resolve，页面在跳转期间不再处理这次请求，
  // 界面上也就不会闪出一条错误提示。
  if (resp.status === 401 && !LOGIN_URL.test(url)) {
    const target = window.location.pathname + window.location.search
    window.location.assign('/login?redirect=' + encodeURIComponent(target))
    return new Promise(() => {})
  }
  let body = null
  try {
    body = await resp.json()
  } catch {
    /* 非 JSON 响应（如 302 跳转后的页面）*/
  }
  if (!resp.ok) {
    const detail = body && body.detail ? body.detail : `请求失败（${resp.status}）`
    const err = new ApiError(resp.status, detail)
    err.body = body
    throw err
  }
  return body
}

export const api = {
  me: () => request('/v1/me'),
  meta: () => request('/console/api/meta'),
  sessions: (params = {}) => {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') qs.set(k, v)
    }
    const q = qs.toString()
    return request('/v1/sessions' + (q ? '?' + q : ''))
  },
  session: (id) => request(`/v1/sessions/${encodeURIComponent(id)}`),
  // 仅管理员：导出链路计数 + 审计域库存 + 生效配置。
  metrics: () => request('/internal/metrics'),
  auditLog: (params = {}) => {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') qs.set(k, v)
    }
    const q = qs.toString()
    return request('/v1/audit-log' + (q ? '?' + q : ''))
  },
  reveal: (entityId) =>
    request(`/v1/reveal/${encodeURIComponent(entityId)}`, { method: 'POST' }),
  loginTest: (username, password) =>
    request('/console/api/login/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    }),
  adminLogin: (username, password) =>
    request('/v1/admin/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    }),
  logout: () => request('/console/api/logout', { method: 'POST' }),
  adminLogout: () => request('/v1/admin/logout', { method: 'POST' })
}
