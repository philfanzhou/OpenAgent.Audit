<script setup>
import { ref, watch, onMounted, onBeforeUnmount } from "vue";
import { api } from "../api.js";
import Pager from "../components/Pager.vue";
import SearchBox from "../components/SearchBox.vue";

const sessions = ref([]);
const total = ref(0);
const page = ref(1);
const pageSize = 10;
const q = ref("");
const range = ref("");          // '' | '24h' | '7d' | '30d'
const demoHidden = ref(false);
const browseBlocked = ref(false);
const browseThreshold = ref(200);
const error = ref("");
const loading = ref(true);
let ticker = null;

function fromTsIso() {
  if (!range.value) return undefined;
  const hours = range.value === "24h" ? 24 : range.value === "7d" ? 168 : 720;
  return new Date(Date.now() - hours * 3600_000).toISOString();
}

async function load() {
  loading.value = true;
  error.value = "";
  try {
    const data = await api.sessions({
      page: page.value, page_size: pageSize,
      q: q.value || undefined,
      from_ts: fromTsIso(),
    });
    sessions.value = data.sessions;
    total.value = data.total;
    demoHidden.value = !!data.demo_hidden;
    browseBlocked.value = !!data.browse_blocked;
    browseThreshold.value = data.browse_threshold ?? 200;
  } catch (e) {
    error.value = e.message;
  } finally {
    loading.value = false;
  }
}

watch([q, range], () => { page.value = 1; load(); });
onMounted(() => {
  load();
  ticker = setInterval(load, 30_000); // keep "最近活跃" fresh while browsing
});
onBeforeUnmount(() => { if (ticker) clearInterval(ticker); });

const RANGES = [
  { value: "", label: "全部时间" },
  { value: "24h", label: "最近 24 小时" },
  { value: "7d", label: "最近 7 天" },
  { value: "30d", label: "最近 30 天" },
];

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

    <!-- filters -->
    <div class="flex items-center gap-2 mb-4 flex-wrap">
      <div class="inline-flex rounded-lg border border-slate-300 overflow-hidden text-sm">
        <button v-for="r in RANGES" :key="r.value" @click="range = r.value"
          class="px-3 py-1.5"
          :class="range === r.value ? 'bg-blue-600 text-white' : 'bg-white text-slate-600 hover:bg-slate-50'">
          {{ r.label }}
        </button>
      </div>
    </div>

    <!-- search-first: unconditional browsing disabled beyond threshold -->
    <div v-if="browseBlocked"
      class="rounded-xl bg-white shadow p-10 text-center mb-4">
      <p class="text-lg font-semibold text-slate-700">会话量较大（共 {{ total }} 条）</p>
      <p class="mt-2 text-sm text-slate-500 leading-relaxed">
        超过直接浏览上限（{{ browseThreshold }} 条）。<br />
        请使用上方搜索框输入关键词，或选择时间范围 / agent 标签缩小范围后查看。
      </p>
    </div>

    <p v-else-if="loading" class="text-slate-500">加载中…</p>
    <p v-else-if="error" class="text-red-600">{{ error }}</p>
    <p v-else-if="!sessions.length" class="text-slate-500">
      {{ q || range ? "没有匹配的会话。" : "暂无会话数据。" }}
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
