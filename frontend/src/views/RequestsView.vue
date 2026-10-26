<script setup>
import { ref, computed, watch, onMounted, onBeforeUnmount } from "vue";
import { api } from "../api.js";
import { auth } from "../store.js";
import Pager from "../components/Pager.vue";
import SearchBox from "../components/SearchBox.vue";

const requests = ref([]);
const total = ref(0);
const page = ref(1);
const pageSize = 10;
const q = ref("");
const error = ref("");
const message = ref("");
const loading = ref(true);

// create-request form
const showForm = ref(false);
const form = ref({ object_type: "entity", object_id: "", reason: "" });

// reveal result (single plaintext, never persisted)
const revealed = ref(null); // { request_id, plaintext }

const canManage = computed(() => auth.isComplianceLead);

const STATUS = {
  pending: ["待审批", "bg-amber-100 text-amber-700"],
  approved: ["已批准", "bg-blue-100 text-blue-700"],
  rejected: ["已驳回", "bg-red-100 text-red-700"],
  fulfilled: ["已还原", "bg-emerald-100 text-emerald-700"],
};

async function load() {
  loading.value = true;
  try {
    const data = await api.restoreRequests({
      page: page.value, page_size: pageSize, q: q.value || undefined,
    });
    requests.value = data.requests;
    total.value = data.total;
    if (data.requests.length === 0 && page.value > 1) {
      page.value = 1; load(); // 当前页被搜索/删除清空时回退到第一页
    }
  } catch (e) {
    error.value = e.message;
  } finally {
    loading.value = false;
  }
}

async function submit() {
  error.value = "";
  message.value = "";
  try {
    await api.createRestoreRequest({ ...form.value });
    message.value = "还原申请已提交，等待另一位合规主管审批。";
    showForm.value = false;
    form.value = { object_type: "entity", object_id: "", reason: "" };
    await load();
  } catch (e) {
    error.value = e.message;
  }
}

async function decide(req, approve) {
  error.value = "";
  message.value = "";
  const comment = window.prompt(approve ? "审批意见（可选）：" : "驳回理由：") ?? "";
  if (!approve && !comment.trim()) { error.value = "驳回必须填写理由。"; return; }
  try {
    await (approve ? api.approve(req.id, comment) : api.reject(req.id, comment));
    await load();
  } catch (e) {
    error.value = e.message;
  }
}

async function reveal(req) {
  error.value = "";
  message.value = "";
  try {
    const result = await api.reveal(req.id);
    revealed.value = { request_id: req.id, plaintext: result.plaintext || "(二进制内容，请经 API 下载)" };
    await load(); // refresh reveal_expires_at countdown
  } catch (e) {
    if (e.status === 410) {
      error.value = "还原查看窗口已过期（超过 TTL）。请重新提交一条还原申请并再次审批。";
    } else {
      error.value = e.message;
    }
  }
}

// TTL helpers: the reveal window is set at first reveal and enforced
// server-side (audit-api + decrypt-svc); here we display a live countdown.
const nowMs = ref(Date.now());
let ticker = null;
watch(q, () => { page.value = 1; load(); });
onMounted(() => {
  load();
  ticker = setInterval(() => { nowMs.value = Date.now(); }, 1000);
});
onBeforeUnmount(() => { if (ticker) clearInterval(ticker); });

function expiry(req) {
  return req.reveal_expires_at ? new Date(req.reveal_expires_at) : null;
}

function isExpired(req) {
  const exp = expiry(req);
  return exp !== null && exp.getTime() <= nowMs.value;
}

function ttlText(req) {
  const exp = expiry(req);
  if (!exp) return "";
  const ms = exp.getTime() - nowMs.value;
  if (ms <= 0) return "查看窗口已过期";
  const min = Math.floor(ms / 60000);
  const sec = Math.floor((ms % 60000) / 1000);
  return min > 0 ? `查看窗口剩余 ${min} 分 ${sec} 秒` : `查看窗口剩余 ${sec} 秒`;
}

// 四眼提示：自己提交、还在等另一位合规主管处理的申请数
const myPendingCount = computed(() =>
  requests.value.filter(
    (r) => r.status === "pending" && r.requested_by === auth.username
  ).length
);

// object id: full display + one-click copy (it is exactly what the
// restore-request form's 对象ID asks for)
const copiedId = ref("");
async function copyObjectId(req) {
  try {
    await navigator.clipboard.writeText(req.object_id);
    copiedId.value = req.id;
    setTimeout(() => { if (copiedId.value === req.id) copiedId.value = ""; }, 1500);
  } catch {
    // clipboard API unavailable (non-secure context) — select-for-copy fallback
    window.prompt("请手动复制对象 ID：", req.object_id);
  }
}
</script>

<template>
  <div>
    <div class="flex items-center justify-between mb-1 flex-wrap gap-3">
      <h1 class="text-2xl font-bold text-slate-800">还原审批</h1>
      <div class="flex items-center gap-3">
        <SearchBox v-model="q" placeholder="搜索对象 ID / 理由 / 申请人 / 审批人" />
        <button v-if="canManage" @click="showForm = !showForm"
          class="rounded-lg bg-blue-600 text-white px-4 py-2 text-sm font-medium hover:bg-blue-700">
          {{ showForm ? "取消" : "+ 新建还原申请" }}
        </button>
      </div>
    </div>
    <p class="text-sm text-slate-500 mb-6">
      单条还原需两位合规主管（四眼原则），解密由 decrypt-svc 独立执行并全程留痕。
    </p>

    <!-- create form -->
    <form v-if="showForm && canManage" @submit.prevent="submit"
      class="bg-white rounded-xl shadow p-5 mb-6 space-y-4 max-w-xl">
      <div>
        <label class="block text-sm text-slate-600 mb-1">对象类型</label>
        <select v-model="form.object_type" class="w-48 rounded-lg border border-slate-300 px-3 py-2 text-sm">
          <option value="entity">文本实体（密文表编号）</option>
          <option value="media">媒体对象（s3:// key）</option>
        </select>
      </div>
      <div>
        <label class="block text-sm text-slate-600 mb-1">对象 ID</label>
        <input v-model="form.object_id" required
          placeholder="在「会话审计 → 会话详情」中点击实体芯片即可复制"
          class="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm font-mono" />
      </div>
      <div>
        <label class="block text-sm text-slate-600 mb-1">申请理由（必填）</label>
        <textarea v-model="form.reason" required rows="2"
          class="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"></textarea>
      </div>
      <button type="submit" class="rounded-lg bg-blue-600 text-white px-4 py-2 text-sm hover:bg-blue-700">
        提交申请
      </button>
    </form>

    <p v-if="message" class="mb-4 rounded-lg bg-emerald-50 text-emerald-700 px-4 py-2 text-sm">{{ message }}</p>
    <p v-if="error" class="mb-4 rounded-lg bg-red-50 text-red-700 px-4 py-2 text-sm">{{ error }}</p>
    <p v-if="myPendingCount > 0" class="mb-4 rounded-lg bg-amber-50 text-amber-700 px-4 py-2 text-sm">
      您有 {{ myPendingCount }} 条申请待处理：四眼原则要求由另一位合规主管审批（您本人无法批准自己的申请），请对方登录后在本页操作。
    </p>

    <!-- reveal result -->
    <div v-if="revealed" class="mb-6 rounded-xl border-2 border-amber-300 bg-amber-50 p-5 max-w-xl">
      <div class="flex items-center justify-between mb-2">
        <span class="text-sm font-semibold text-amber-800">已解密内容（仅本次显示，不会保存）</span>
        <button @click="revealed = null" class="text-amber-700 hover:text-amber-900 text-sm">关闭</button>
      </div>
      <p class="font-mono text-lg text-slate-800">{{ revealed.plaintext }}</p>
      <p class="mt-2 text-xs text-amber-700">申请单 {{ revealed.request_id }} · 本次查看已写入审计日志</p>
    </div>

    <p v-if="loading" class="text-slate-500">加载中…</p>
    <p v-else-if="!requests.length" class="text-slate-500">
      {{ q ? "没有匹配的还原申请。" : "暂无还原申请。" }}
    </p>

    <template v-else>
    <div class="bg-white rounded-xl shadow overflow-hidden">
      <table class="w-full text-sm">
        <thead class="bg-slate-50 text-slate-500 text-left">
          <tr>
            <th class="px-4 py-3">状态</th>
            <th class="px-4 py-3">对象</th>
            <th class="px-4 py-3">理由</th>
            <th class="px-4 py-3">申请人</th>
            <th class="px-4 py-3">审批人</th>
            <th class="px-4 py-3">操作</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-slate-100">
          <tr v-for="r in requests" :key="r.id">
            <td class="px-4 py-3">
              <span class="px-2 py-0.5 rounded-full text-xs" :class="STATUS[r.status]?.[1]">
                {{ STATUS[r.status]?.[0] || r.status }}
              </span>
            </td>
            <td class="px-4 py-3">
              <span class="px-1.5 py-0.5 rounded bg-slate-100 text-xs mr-1">
                {{ r.object_type === "entity" ? "文本实体" : "媒体" }}
              </span>
              <span class="font-mono text-xs break-all">{{ r.object_id }}</span>
              <button @click="copyObjectId(r)" :title="'复制对象 ID：' + r.object_id"
                class="ml-1 text-blue-600 hover:text-blue-800 text-xs align-middle">
                {{ copiedId === r.id ? "✓ 已复制" : "复制" }}
              </button>
            </td>
            <td class="px-4 py-3 max-w-xs truncate" :title="r.reason">{{ r.reason }}</td>
            <td class="px-4 py-3">{{ r.requested_by }}</td>
            <td class="px-4 py-3">{{ r.approver || "—" }}</td>
            <td class="px-4 py-3 space-x-2 whitespace-nowrap text-xs">
              <template v-if="canManage">
                <template v-if="r.status === 'pending'">
                  <template v-if="r.requested_by === auth.username">
                    <span class="text-slate-400">我提交的申请 · 等待另一位合规主管审批（四眼原则，不能自批）</span>
                  </template>
                  <template v-else>
                    <button @click="decide(r, true)"
                      class="rounded bg-emerald-600 text-white px-2.5 py-1 text-xs hover:bg-emerald-700">批准</button>
                    <button @click="decide(r, false)"
                      class="rounded bg-red-600 text-white px-2.5 py-1 text-xs hover:bg-red-700">驳回</button>
                  </template>
                </template>
                <template v-else>
                  <button v-if="(r.status === 'approved' || r.status === 'fulfilled') && !isExpired(r)"
                    @click="reveal(r)"
                    class="rounded bg-blue-600 text-white px-2.5 py-1 text-xs hover:bg-blue-700">查看原文</button>
                  <span v-if="r.status === 'fulfilled'" class="text-xs"
                    :class="isExpired(r) ? 'text-red-500' : 'text-slate-400'">{{ ttlText(r) }}</span>
                </template>
              </template>
              <span v-else class="text-slate-400">
                {{ auth.role === "developer" ? "只读视图 · 还原操作仅限合规主管" : "仅合规主管可操作" }}
              </span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <Pager :page="page" :page-size="pageSize" :total="total" @change="(p) => { page = p; load(); }" />
    </template>
  </div>
</template>
