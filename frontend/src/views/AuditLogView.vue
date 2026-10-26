<script setup>
import { ref, watch, onMounted } from "vue";
import { api } from "../api.js";
import Pager from "../components/Pager.vue";
import SearchBox from "../components/SearchBox.vue";

const entries = ref([]);
const total = ref(0);
const page = ref(1);
const pageSize = 10;
const q = ref("");
const verification = ref(null);
const verifying = ref(false);
const error = ref("");
const loading = ref(true);

const ACTION_LABELS = {
  SESSION_VIEWED: "浏览会话",
  RESTORE_REQUESTED: "提交还原申请",
  RESTORE_APPROVED: "批准还原",
  RESTORE_REJECTED: "驳回还原",
  RESTORE_DECRYPTED: "解密实体",
  MEDIA_DECRYPTED: "解密媒体",
  RESTORE_VIEWED: "查看还原内容",
  DECRYPT_PERFORMED: "执行解密",
  RETENTION_RUN: "保留期任务",
};

async function load() {
  loading.value = true;
  error.value = "";
  try {
    const data = await api.auditLog({ page: page.value, page_size: pageSize, q: q.value || undefined });
    entries.value = data.entries;
    total.value = data.total;
  } catch (e) {
    error.value = e.message;
  } finally {
    loading.value = false;
  }
}

// full hash-chain check — independent of paging, run on demand
async function verifyChain() {
  verifying.value = true;
  try {
    const data = await api.auditLog({ page: 1, page_size: 1, verify: true });
    verification.value = data.verification;
  } catch (e) {
    error.value = e.message;
  } finally {
    verifying.value = false;
  }
}

watch(q, () => { page.value = 1; load(); });
onMounted(() => { load(); verifyChain(); });

function fmt(ts) {
  return ts ? new Date(ts).toLocaleString("zh-CN") : "-";
}
</script>

<template>
  <div>
    <div class="flex items-center justify-between mb-1 flex-wrap gap-3">
      <h1 class="text-2xl font-bold text-slate-800">审计日志</h1>
      <div class="flex items-center gap-3">
        <SearchBox v-model="q" placeholder="搜索操作者 / 动作 / 对象" />
        <button @click="verifyChain" :disabled="verifying"
          class="rounded-lg border border-slate-300 px-3 py-2 text-sm hover:bg-slate-50 disabled:opacity-50">
          {{ verifying ? "校验中…" : "校验哈希链" }}
        </button>
      </div>
    </div>
    <p class="text-sm text-slate-500 mb-4">
      append-only + 哈希链，任何删改都可被发现；正本定期归档到 Object-Lock 存储桶。
    </p>

    <p v-if="loading" class="text-slate-500">加载中…</p>
    <p v-else-if="error" class="text-red-600">{{ error }}</p>

    <template v-else>
      <div v-if="verification" class="mb-4 rounded-lg px-4 py-2.5 text-sm inline-flex items-center gap-2"
        :class="verification.ok ? 'bg-emerald-50 text-emerald-700' : 'bg-red-50 text-red-700'">
        <span>{{ verification.ok ? "✓ 哈希链完整" : "✗ 哈希链校验失败！" }}</span>
        <span v-if="verification.ok" class="text-emerald-600">
          已校验全部 {{ verification.entries }} 条记录
        </span>
        <span v-else>首个异常记录 seq = {{ verification.first_bad_seq }}</span>
      </div>

      <p v-if="!entries.length" class="text-slate-500">
        {{ q ? "没有匹配的审计记录。" : "暂无审计记录。" }}
      </p>

      <template v-else>
        <div class="bg-white rounded-xl shadow overflow-x-auto">
          <table class="w-full text-sm">
            <thead class="bg-slate-50 text-slate-500 text-left">
              <tr>
                <th class="px-4 py-3">#</th>
                <th class="px-4 py-3">时间</th>
                <th class="px-4 py-3">操作者</th>
                <th class="px-4 py-3">角色</th>
                <th class="px-4 py-3">动作</th>
                <th class="px-4 py-3">对象</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-100">
              <tr v-for="e in entries" :key="e.seq" class="hover:bg-slate-50">
                <td class="px-4 py-2.5 text-slate-400 font-mono text-xs">{{ e.seq }}</td>
                <td class="px-4 py-2.5 text-slate-500 whitespace-nowrap">{{ fmt(e.ts) }}</td>
                <td class="px-4 py-2.5">{{ e.actor }}</td>
                <td class="px-4 py-2.5 text-slate-500">{{ e.role }}</td>
                <td class="px-4 py-2.5">
                  <span class="px-2 py-0.5 rounded-full bg-slate-100 text-xs">
                    {{ ACTION_LABELS[e.action] || e.action }}
                  </span>
                </td>
                <td class="px-4 py-2.5 font-mono text-xs text-slate-500">
                  {{ e.object_type }}{{ e.object_id ? `: ${e.object_id.slice(0, 20)}` : "" }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <Pager :page="page" :page-size="pageSize" :total="total" @change="(p) => { page = p; load(); }" />
      </template>
    </template>
  </div>
</template>
