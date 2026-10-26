<script setup>
import { useRouter } from "vue-router";
import { auth, ROLE_LABELS } from "./store.js";

const router = useRouter();

function logout() {
  auth.logout();
  router.push("/login");
}
</script>

<template>
  <div class="min-h-screen flex flex-col">
    <header class="bg-slate-900 text-white shadow">
      <div class="mx-auto max-w-6xl px-6 h-14 flex items-center gap-6">
        <router-link to="/sessions" class="flex items-center gap-2 font-semibold">
          <span class="inline-block w-2.5 h-2.5 rounded-full bg-emerald-400"></span>
          OpenAgent 审计平台
        </router-link>
        <nav class="flex gap-1 text-sm" v-if="auth.token">
          <router-link to="/sessions" class="px-3 py-1.5 rounded hover:bg-slate-700"
            :class="{ 'bg-slate-700': $route.path.startsWith('/sessions') }">会话审计</router-link>
          <router-link to="/requests" class="px-3 py-1.5 rounded hover:bg-slate-700"
            :class="{ 'bg-slate-700': $route.path.startsWith('/requests') }">还原审批</router-link>
          <router-link to="/audit-log" class="px-3 py-1.5 rounded hover:bg-slate-700"
            :class="{ 'bg-slate-700': $route.path.startsWith('/audit-log') }">审计日志</router-link>
          <router-link v-if="auth.role === 'developer'" to="/metrics"
            class="px-3 py-1.5 rounded hover:bg-slate-700"
            :class="{ 'bg-slate-700': $route.path.startsWith('/metrics') }">运行指标</router-link>
        </nav>
        <div class="ml-auto flex items-center gap-3 text-sm" v-if="auth.token">
          <span class="text-slate-300">
            {{ auth.username }}
            <span class="ml-1 px-2 py-0.5 rounded-full bg-slate-700 text-xs">{{ ROLE_LABELS[auth.role] || auth.role }}</span>
          </span>
          <button @click="logout" class="px-3 py-1.5 rounded bg-slate-700 hover:bg-slate-600">退出</button>
        </div>
      </div>
    </header>
    <main class="flex-1 mx-auto w-full max-w-6xl px-6 py-8">
      <router-view />
    </main>
    <footer class="py-4 text-center text-xs text-slate-400">
      展示时脱敏（模式 B）· 敏感信息以编号 + 掩码显示，还原需审批并全程留痕
    </footer>
  </div>
</template>
