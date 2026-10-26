<script setup>
import { ref } from "vue";
import { useRouter } from "vue-router";
import { api } from "../api.js";
import { auth } from "../store.js";

const router = useRouter();
const token = ref("");
const error = ref("");
const loading = ref(false);

async function login() {
  error.value = "";
  loading.value = true;
  try {
    // validate the token against /v1/me, then keep it as the bearer
    const me = await fetch("/v1/me", { headers: { Authorization: `Bearer ${token.value.trim()}` } });
    if (!me.ok) throw new Error("令牌无效或已过期");
    const principal = await me.json();
    auth.setLogin(token.value.trim(), principal.username, principal.role);
    router.push("/sessions");
  } catch (e) {
    error.value = e.message || "登录失败";
  } finally {
    loading.value = false;
  }
}
</script>

<template>
  <div class="min-h-screen flex items-center justify-center bg-slate-100">
    <div class="w-full max-w-sm bg-white rounded-xl shadow-lg p-8">
      <h1 class="text-xl font-bold text-slate-800 mb-1">OpenAgent 审计平台</h1>
      <p class="text-sm text-slate-500 mb-6">请输入访问令牌登录</p>
      <form @submit.prevent="login" class="space-y-4">
        <input
          v-model="token"
          type="password"
          placeholder="访问令牌"
          class="w-full rounded-lg border border-slate-300 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
          required
        />
        <p v-if="error" class="text-sm text-red-600">{{ error }}</p>
        <button
          type="submit"
          :disabled="loading"
          class="w-full rounded-lg bg-blue-600 text-white py-2 font-medium hover:bg-blue-700 disabled:opacity-50"
        >
          {{ loading ? "登录中…" : "登录" }}
        </button>
      </form>
      <div class="mt-6 text-xs text-slate-400 leading-relaxed">
        <p>演示账号（本地环境）：</p>
        <p>审计员 alice：tok-auditor ｜ 合规主管 bob / carol：tok-lead / tok-lead2</p>
        <p>开发者·只读管理员 dan：tok-dev（全站只读 + 运行指标）</p>
      </div>
    </div>
  </div>
</template>
