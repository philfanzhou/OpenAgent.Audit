<script setup>
import { ref, onMounted } from "vue";
import { useRoute } from "vue-router";
import { api } from "../api.js";

const route = useRoute();
const traces = ref([]);
const error = ref("");
const loading = ref(true);

// Render entity chips: split text into plain parts and ⟦TYPE#id|mask⟧ chips.
// Clicking a chip copies the full entity id — exactly the 对象ID the restore
// request form asks for.
const copiedId = ref("");

function parts(text) {
  if (typeof text !== "string") return [{ plain: JSON.stringify(text) }];
  const out = [];
  const re = /⟦([A-Z_]+)#([0-9a-f]+)\|([^⟧]*)⟧/g;
  let last = 0;
  let m;
  const labels = {
    PHONE_NUMBER: "电话", CN_PHONE: "电话", ID_CARD: "身份证",
    BANK_CARD: "银行卡", EMAIL_ADDRESS: "邮箱", PERSON: "姓名",
  };
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) out.push({ plain: text.slice(last, m.index) });
    out.push({ chip: true, type: labels[m[1]] || m[1], mask: m[3], id: m[2] });
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push({ plain: text.slice(last) });
  return out;
}

async function copyEntityId(p) {
  try {
    await navigator.clipboard.writeText(p.id);
  } catch {
    window.prompt("请手动复制对象 ID：", p.id);
  }
  copiedId.value = p.id;
  setTimeout(() => { if (copiedId.value === p.id) copiedId.value = ""; }, 1500);
}

onMounted(async () => {
  try {
    traces.value = (await api.session(route.params.sessionId)).traces;
  } catch (e) {
    error.value = e.message;
  } finally {
    loading.value = false;
  }
});

function fmt(ts) {
  return ts ? new Date(ts).toLocaleString("zh-CN") : "-";
}
</script>

<template>
  <div>
    <router-link to="/sessions" class="text-sm text-blue-600 hover:underline">← 返回会话列表</router-link>
    <h1 class="text-2xl font-bold text-slate-800 mt-2 mb-6">
      会话 <span class="font-mono text-lg">{{ route.params.sessionId }}</span>
    </h1>

    <p v-if="loading" class="text-slate-500">加载中…</p>
    <p v-else-if="error" class="text-red-600">{{ error }}</p>

    <div v-else class="space-y-6">
      <div v-for="t in traces" :key="t.trace_id" class="bg-white rounded-xl shadow p-5">
        <div class="flex items-center gap-3 mb-4 text-sm text-slate-500">
          <span class="px-2 py-0.5 rounded bg-blue-50 text-blue-700 text-xs">{{ t.name }}</span>
          <span class="font-mono text-xs">{{ t.trace_id }}</span>
          <span>用户 {{ t.user_id }}</span>
          <span>{{ fmt(t.timestamp) }}</span>
        </div>
        <div class="space-y-3">
          <div v-for="o in t.observations" :key="o.id" class="border border-slate-100 rounded-lg p-3">
            <div class="flex items-center gap-2 text-xs text-slate-400 mb-1.5">
              <span class="px-1.5 py-0.5 rounded bg-slate-100">{{ o.type === "generation" ? "LLM 调用" : "步骤" }}</span>
              <span>{{ o.name }}</span>
              <span v-if="o.model">{{ o.model }}</span>
              <span v-if="o.latency_ms">{{ (o.latency_ms / 1000).toFixed(1) }}s</span>
              <span v-if="o.usage && o.usage.input">tokens {{ o.usage.input }} → {{ o.usage.output }}</span>
            </div>
            <div v-if="o.input !== null && o.input !== undefined" class="text-sm leading-7 text-slate-700">
              <span class="text-slate-400 mr-1">输入:</span>
              <template v-for="(p, i) in parts(o.input)" :key="i">
                <span v-if="p.plain">{{ p.plain }}</span>
                <button v-else @click="copyEntityId(p)" title="点击复制对象 ID（用于还原申请）"
                  class="inline-flex items-center mx-0.5 px-1.5 rounded border border-dashed hover:border-blue-400 hover:text-blue-700 border-slate-300 bg-slate-50 text-slate-500 text-xs align-middle">
                  {{ p.type }} · {{ p.mask }}
                  <span v-if="copiedId === p.id" class="ml-1 text-blue-600">✓已复制</span>
                </button>
              </template>
            </div>
            <div v-if="o.output !== null && o.output !== undefined" class="text-sm leading-7 text-slate-700 mt-1">
              <span class="text-slate-400 mr-1">输出:</span>
              <template v-for="(p, i) in parts(o.output)" :key="i">
                <span v-if="p.plain">{{ p.plain }}</span>
                <button v-else @click="copyEntityId(p)" title="点击复制对象 ID（用于还原申请）"
                  class="inline-flex items-center mx-0.5 px-1.5 rounded border border-dashed hover:border-blue-400 hover:text-blue-700 border-slate-300 bg-slate-50 text-slate-500 text-xs align-middle">
                  {{ p.type }} · {{ p.mask }}
                  <span v-if="copiedId === p.id" class="ml-1 text-blue-600">✓已复制</span>
                </button>
              </template>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
