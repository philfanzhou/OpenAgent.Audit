import { reactive } from 'vue'
import { ElMessageBox } from 'element-plus'

// 会话级共享状态：当前登录身份 + 管理员解锁状态。
// 登录态由服务端 Cookie 会话承载，这里只做展示层的镜像。
export const auth = reactive({
  loaded: false,
  username: '',
  role: '',
  roleLabel: '',
  isAdmin: false,
  canStepUpToAdmin: false,
  // 管理员解锁的到期时刻（浏览器本地毫秒时间戳）；0 = 未解锁。
  adminExpiresAt: 0,
  adminSessionMinutes: 30,
  zoneLabel: 'CST+08:00',
  ssoEnabled: false
})

export function setPrincipal(me) {
  auth.loaded = true
  auth.username = me.username
  auth.role = me.role
  auth.roleLabel = me.role_label
  auth.isAdmin = me.is_admin
  auth.canStepUpToAdmin = me.can_step_up_to_admin
  auth.adminSessionMinutes = me.admin_session_minutes || 30
  if (me.is_admin && me.admin_expires_in > 0) {
    // 服务端给出的是剩余秒数；以本地时间推算到期时刻。
    armAdminExpiry(me.admin_expires_in)
  } else {
    disarmAdminExpiry()
  }
}

export function clearPrincipal() {
  disarmAdminExpiry()
  auth.loaded = true
  auth.username = ''
  auth.role = ''
  auth.roleLabel = ''
  auth.isAdmin = false
  auth.canStepUpToAdmin = false
}

// ── 管理员到期：服务端到点会把会话降回普通用户；这里同步在浏览器里收口 ──
// 到期瞬间：撤掉管理员界面、弹窗说明，并要求刷新网页。后台标签页的定时器
// 可能被浏览器节流，所以切回前台时再核对一次到期时刻。

let expiryTimer = null
let expiryDialogOpen = false

function expireAdmin() {
  if (expiryDialogOpen) return
  expiryDialogOpen = true
  disarmAdminExpiry()
  auth.isAdmin = false
  auth.adminExpiresAt = 0
  auth.canStepUpToAdmin = true
  const minutes = auth.adminSessionMinutes
  ElMessageBox.alert(
    `管理员账号登录已满 ${minutes} 分钟，已自动退出管理员账号。请刷新网页后继续使用；如仍需管理员权限，请重新登录管理员。`,
    '管理员登录已到期',
    {
      confirmButtonText: '刷新网页',
      type: 'warning',
      showClose: false,
      closeOnPressEscape: false,
      closeOnClickModal: false
    }
  ).then(() => window.location.reload(), () => window.location.reload())
}

function checkAdminExpiry() {
  if (!auth.isAdmin || !auth.adminExpiresAt) return
  if (Date.now() >= auth.adminExpiresAt) expireAdmin()
}

export function armAdminExpiry(expiresInSeconds) {
  auth.adminExpiresAt = Date.now() + expiresInSeconds * 1000
  expiryDialogOpen = false
  if (expiryTimer) clearTimeout(expiryTimer)
  expiryTimer = setTimeout(checkAdminExpiry, Math.max(expiresInSeconds * 1000, 0))
}

export function disarmAdminExpiry() {
  if (expiryTimer) clearTimeout(expiryTimer)
  expiryTimer = null
  auth.adminExpiresAt = 0
}

if (typeof document !== 'undefined') {
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) checkAdminExpiry()
  })
}
