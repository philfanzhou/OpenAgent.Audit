<script setup>
import { ref, computed, onBeforeUnmount } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessageBox, ElMessage } from 'element-plus'
import { api } from './api'
import { auth, armAdminExpiry, clearPrincipal } from './store'

const router = useRouter()

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

// 身份信息由路由守卫在进入页面前加载（见 router.js），这里不再重复请求。

// 退出：即使服务端会话已经失效（401），也要清掉本地状态并回到登录页。
async function logout() {
  try {
    await api.logout()
  } catch {
    /* 会话已失效：本地照样退出 */
  } finally {
    clearPrincipal()
    router.push('/login')
  }
}

async function adminLogout() {
  try {
    await api.adminLogout()
    ElMessage.success('已退出管理员')
  } catch (err) {
    ElMessage.error(err.message || '退出管理员失败')
  } finally {
    auth.isAdmin = false
    auth.canStepUpToAdmin = true
    auth.adminExpiresAt = 0
  }
}

function adminStepUp() {
  ElMessageBox.prompt('请输入管理员密码', '登录管理员', {
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
