<script setup>
import { onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessageBox, ElMessage } from 'element-plus'
import { api } from './api'
import { auth, clearPrincipal } from './store'

const router = useRouter()

onMounted(async () => {
  // 预热身份信息（登录页之外的页面都需要）
  if (!auth.loaded && router.currentRoute.value.path !== '/login') {
    try {
      const me = await api.me()
      Object.assign(auth, {
        loaded: true,
        username: me.username,
        role: me.role,
        roleLabel: me.role_label,
        isAdmin: me.is_admin,
        canStepUpToAdmin: me.can_step_up_to_admin
      })
    } catch {
      /* 未登录由路由守卫处理 */
    }
  }
})

async function logout() {
  await api.logout()
  clearPrincipal()
  router.push('/login')
}

async function adminLogout() {
  await api.adminLogout()
  auth.isAdmin = false
  auth.canStepUpToAdmin = false
  ElMessage.success('已退出管理员')
}

function adminStepUp() {
  ElMessageBox.prompt('账号：admin\n请输入管理员密码', '登录管理员', {
    inputType: 'password',
    inputPlaceholder: '管理员密码',
    confirmButtonText: '登录',
    cancelButtonText: '取消'
  })
    .then(({ value }) => api.adminLogin(auth.username, value))
    .then(() => {
      auth.isAdmin = true
      ElMessage.success('管理员已解锁，点击脱敏内容可查看原文（每次查看都会记录审计日志）')
    })
    .catch((err) => {
      if (err !== 'cancel' && err) ElMessage.error(err.message || '管理员登录失败')
    })
}
</script>

<template>
  <header class="app-header">
    <span class="brand">OpenAgent 审计台</span>
    <nav class="d-flex gap-1" style="flex: 1">
      <router-link class="nav-link" to="/sessions">会话</router-link>
      <router-link v-if="auth.isAdmin" class="nav-link" to="/audit-log">审计日志</router-link>
    </nav>
    <div v-if="auth.username" class="d-flex align-items-center gap-2">
      <span class="text-secondary small">{{ auth.username }}</span>
      <span class="small text-secondary">{{ auth.roleLabel }}</span>
      <el-button v-if="auth.isAdmin" size="small" @click="adminLogout">退出管理员</el-button>
      <el-button v-else-if="auth.canStepUpToAdmin" size="small" @click="adminStepUp">登录管理员</el-button>
      <el-button size="small" text @click="logout">退出</el-button>
    </div>
  </header>

  <router-view />
</template>
