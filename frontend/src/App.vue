<script setup>
import { ref, computed, onMounted, onBeforeUnmount } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessageBox, ElMessage } from 'element-plus'
import { api } from './api'
import { auth, armAdminExpiry, clearPrincipal, setPrincipal } from './store'

const router = useRouter()

onMounted(async () => {
  // 预热身份信息（登录页之外的页面都需要）
  if (!auth.loaded && router.currentRoute.value.path !== '/login') {
    try {
      setPrincipal(await api.me())
    } catch {
      /* 未登录由路由守卫处理 */
    }
  }
})

// 顶栏管理员剩余时间：每秒刷新一次。
const nowMs = ref(Date.now())
const ticker = setInterval(() => { nowMs.value = Date.now() }, 1000)
onBeforeUnmount(() => clearInterval(ticker))
const adminRemaining = computed(() => {
  const ms = auth.adminExpiresAt - nowMs.value
  if (!auth.isAdmin || ms <= 0) return ''
  const total = Math.ceil(ms / 1000)
  const m = Math.floor(total / 60)
  const s = total % 60
  return `${m}:${String(s).padStart(2, '0')}`
})
const adminExpiresIn = computed(() => Math.ceil((auth.adminExpiresAt - nowMs.value) / 1000))

async function logout() {
  await api.logout()
  clearPrincipal()
  router.push('/login')
}

async function adminLogout() {
  await api.adminLogout()
  auth.isAdmin = false
  auth.canStepUpToAdmin = true
  auth.adminExpiresAt = 0
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
    .then((res) => {
      auth.isAdmin = true
      // 服务端返回的剩余秒数：到点弹窗并要求刷新。
      armAdminExpiry(res.expires_in)
      auth.adminSessionMinutes = res.admin_session_minutes || 30
      ElMessage.success(`管理员已解锁（${auth.adminSessionMinutes} 分钟后自动退出），点击脱敏内容可查看原文（每次查看都会记录审计日志）`)
    })
    .catch((err) => {
      if (err !== 'cancel' && err) ElMessage.error(err.message || '管理员登录失败')
    })
}
</script>

<template>
  <header class="app-header">
    <span class="brand">OpenAgent 审计台</span>
    <nav class="main-nav">
      <router-link class="nav-link" to="/sessions">会话</router-link>
      <router-link v-if="auth.isAdmin" class="nav-link" to="/audit-log">审计日志</router-link>
      <router-link v-if="auth.isAdmin" class="nav-link" to="/metrics">运行指标</router-link>
    </nav>
    <div v-if="auth.username" class="user-area">
      <span class="text-secondary small">{{ auth.username }}</span>
      <span class="small text-secondary role-label">{{ auth.roleLabel }}</span>
      <span
        v-if="adminRemaining"
        class="small admin-remaining"
        :class="{ 'is-low': adminExpiresIn <= 60 }"
        title="管理员登录剩余时间，到时自动退出"
      >
        剩余 {{ adminRemaining }}
      </span>
      <el-button v-if="auth.isAdmin" size="small" @click="adminLogout">退出管理员</el-button>
      <el-button v-else-if="auth.canStepUpToAdmin" size="small" @click="adminStepUp">登录管理员</el-button>
      <el-button size="small" text @click="logout">退出</el-button>
    </div>
  </header>

  <router-view />
</template>
