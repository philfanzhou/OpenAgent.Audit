import { reactive } from 'vue'

// 会话级共享状态：当前登录身份 + 管理员解锁状态。
// 登录态由服务端 Cookie 会话承载，这里只做展示层的镜像。
export const auth = reactive({
  loaded: false,
  username: '',
  role: '',
  roleLabel: '',
  isAdmin: false,
  canStepUpToAdmin: false,
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
}

export function clearPrincipal() {
  auth.loaded = true
  auth.username = ''
  auth.role = ''
  auth.roleLabel = ''
  auth.isAdmin = false
  auth.canStepUpToAdmin = false
}
