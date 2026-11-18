<script setup>
import { ref, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import { setPrincipal } from '../store'

const router = useRouter()
const route = useRoute()

const ssoEnabled = ref(false)
const openPanels = ref([])
const username = ref('')
const password = ref('')
const loading = ref(false)

onMounted(async () => {
  try {
    const meta = await api.meta()
    ssoEnabled.value = meta.sso_enabled
    if (!meta.sso_enabled) openPanels.value = ['test']
  } catch {
    openPanels.value = ['test']
  }
})

function ssoLogin() {
  // 跳转到服务端的 SSO 入口，由服务端 302 到公司统一登录。
  window.location.href = '/ui/login/sso/start'
}

async function testLogin() {
  loading.value = true
  try {
    const me = await api.loginTest(username.value, password.value)
    setPrincipal({ ...me, can_step_up_to_admin: me.role === 'user' })
    ElMessage.success('登录成功')
    router.push(route.query.redirect || '/sessions')
  } catch (err) {
    ElMessage.error(err.message)
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="login-page">
    <el-card class="login-card" shadow="always">
      <h1 class="login-title">进入审计台</h1>
      <p class="login-sub">会话内容以脱敏形式展示。查看原文需要管理员登录。</p>

      <div v-if="ssoEnabled" class="sso-block">
        <el-button class="sso-btn" type="primary" size="large" @click="ssoLogin">
          用企业账号登录
        </el-button>
        <p class="sso-hint">跳转到公司统一登录，验证后自动返回审计台。</p>
        <el-divider />
      </div>

      <el-collapse v-model="openPanels">
        <el-collapse-item name="test">
          <template #title>
            <span class="test-title">
              用测试账号登录（{{ ssoEnabled ? 'SSO 不可用时备用' : 'OpenAgent 未传递身份时使用' }}）
            </span>
          </template>
          <el-form label-position="top" @submit.prevent="testLogin">
            <el-form-item label="测试账号">
              <el-input v-model="username" autocomplete="username" placeholder="test" />
            </el-form-item>
            <el-form-item label="测试账号密码">
              <el-input
                v-model="password"
                type="password"
                autocomplete="current-password"
                show-password
              />
            </el-form-item>
            <el-text size="small" type="info" class="test-note">
              仅为普通用户，<strong>不能</strong>登录管理员，1 小时后自动退出。
            </el-text>
            <el-button class="w-100 mt-2" type="primary" :loading="loading" native-type="submit">
              用测试账号登录
            </el-button>
          </el-form>
        </el-collapse-item>
      </el-collapse>
    </el-card>
  </div>
</template>

<style scoped>
.login-page { max-width: 520px; margin: 12vh auto; padding: 0 16px; }
.login-title { font-size: 20px; font-weight: 700; margin: 0 0 4px; }
.login-sub { color: #94a3b8; font-size: 13px; margin: 0 0 20px; }
.sso-block { margin-bottom: 8px; }
.sso-btn { width: 100%; height: 44px; font-size: 15px; }
.sso-hint { color: #94a3b8; font-size: 12.5px; margin: 8px 0 0; text-align: center; }
.test-title { font-size: 13.5px; color: #475569; }
.test-note { display: block; }
.w-100 { width: 100%; }
.mt-2 { margin-top: 8px; }
</style>
