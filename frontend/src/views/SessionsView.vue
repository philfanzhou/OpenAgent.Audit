<script setup>
import { ref, watch, onMounted } from "vue";
import { api } from "../api.js";
import Pager from "../components/Pager.vue";
import SearchBox from "../components/SearchBox.vue";

const sessions = ref([]);
const total = ref(0);
const page = ref(1);
const pageSize = 10;
const q = ref("");
const demoHidden = ref(false);
const error = ref("");
const loading = ref(true);

async function load() {
  loading.value = true;
  error.value = "";
  try {
    const data = await api.sessions({ page: page.value, page_size: pageSize, q: q.value || undefined });
    sessions.value = data.sessions;
    total.value = data.total;
    demoHidden.value = !!data.demo_hidden;
  } catch (e) {
    error.value = e.message;
  } finally {
    loading.value = false;
  }
}

watch(q, () => { page.value = 1; load(); });
onMounted(load);

function fmt(ts) {
  return ts ? new Date(ts).toLocaleString("zh-CN") : "-";
}
</script>

<template>
  <div>
    <div class="flex items-center justify-between mb-1 flex-wrap gap-3">
      <h1 class="text-2xl font-bold text-slate-800">会话审计</h1>
      <SearchBox v-model="q" placeholder="搜索会话 ID / 用户 / agent 标签" />
    </div>
    <p class="text-sm text-slate-500 mb-4">所有对话均以「编号 + 掩码」展示，全程不接触明文与密文。</p>
    <p v-if="demoHidden" class="mb-4 rounded-lg bg-slate-200 text-slate-600 px-4 py-2 text-xs">
      已接入真实数据：本地演示数据（sess-demo-*）已自动隐藏，需要查看可在地址栏加 include_demo=true。
    </p>

    <p v-if="loading" class="text-slate-500">加载中…</p>
    <p v-else-if="error" class="text-red-600">{{ error }}</p>
    <p v-else-if="!sessions.length" class="text-slate-500">
      {{ q ? "没有匹配的会话。" : "暂无会话数据。" }}
    </p>

    <template v-else>
      <div class="bg-white rounded-xl shadow overflow-hidden">
        <table class="w-full text-sm">
          <thead class="bg-slate-50 text-slate-500 text-left">
            <tr>
              <th class="px-4 py-3">会话 ID</th>
              <th class="px-4 py-3">用户</th>
              <th class="px-4 py-3">请求数</th>
              <th class="px-4 py-3">Agent</th>
              <th class="px-4 py-3">最近活动</th>
              <th class="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-100">
            <tr v-for="s in sessions" :key="s.session_id" class="hover:bg-slate-50">
              <td class="px-4 py-3 font-mono text-xs">{{ s.session_id }}</td>
              <td class="px-4 py-3">{{ s.user_id }}</td>
              <td class="px-4 py-3">{{ s.trace_count }}</td>
              <td class="px-4 py-3">
                <span v-for="t in s.agent_tags" :key="t"
                  class="mr-1 px-2 py-0.5 rounded-full bg-blue-50 text-blue-700 text-xs">{{ t }}</span>
              </td>
              <td class="px-4 py-3 text-slate-500">{{ fmt(s.last_ts) }}</td>
              <td class="px-4 py-3 text-right">
                <router-link :to="`/sessions/${encodeURIComponent(s.session_id)}`"
                  class="text-blue-600 hover:underline">查看</router-link>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <Pager :page="page" :page-size="pageSize" :total="total" @change="(p) => { page = p; load(); }" />
    </template>
  </div>
</template>
