<script setup>
import { ref, onMounted } from "vue";
import { auth } from "../store.js";

const data = ref(null);
const error = ref("");
const denied = ref(false);
const loading = ref(true);

onMounted(async () => {
  try {
    const resp = await fetch("/internal/metrics", {
      headers: { Authorization: `Bearer ${auth.token}` },
    });
    if (resp.status === 403) {
      denied.value = true;
      return;
    }
    if (!resp.ok) throw new Error(`加载失败 (${resp.status})`);
    data.value = await resp.json();
  } catch (e) {
    error.value = e.message;
  } finally {
    loading.value = false;
  }
});

const CARDS = [
  { key: "dropped_batches", label: "导出丢弃批次", danger: true,
    desc: "脱敏钩子异常时整批丢弃（fail-closed），大于 0 必须告警排查" },
  { key: "vault_write_failures", label: "密文写库失败", danger: true,
    desc: "密文表写入重试后仍失败，对应实体将无法还原" },
  { key: "hook_failures", label: "钩子异常次数", desc: "mask_otel_spans 抛异常的总次数" },
  { key: "spans_patched", label: "已脱敏 span 数", desc: "导出线程成功改写的 span 总数" },
  { key: "entities_masked", label: "已脱敏实体数", desc: "识别并生成「编号+掩码+密文」的实体总数" },
  { key: "restores_revealed", label: "还原查看次数", desc: "经审批的原文查看总次数（均留痕）" },
];

const STATUS_LABELS = {
  pending: "待审批", approved: "已批准", rejected: "已驳回", fulfilled: "已还原",
};
const CONFIG_LABELS = {
  reveal_ttl_minutes: "还原查看窗口（分钟）",
  trace_retention_days: "trace 保留期（天）",
  audit_archive_after_days: "审计日志归档阈值（天）",
  trace_store: "trace 数据源",
  pii_backend: "PII 识别后端",
};

function inv(key) {
  const v = data.value?.inventory?.[key];
  return v === null || v === undefined ? "—" : v;
}
</script>

<template>
  <div>
    <h1 class="text-2xl font-bold text-slate-800 mb-1">运行指标</h1>
    <p class="text-sm text-slate-500 mb-6">
      导出链路健康度、审计域库存与合规配置（同一数据源：
      <code class="text-xs">/internal/metrics</code>，可被 Prometheus 抓取告警）。
      开发者角色为只读管理员：可见全部数据，无任何写操作。
    </p>

    <p v-if="loading" class="text-slate-500">加载中…</p>
    <div v-else-if="denied" class="rounded-xl bg-white shadow p-8 text-center">
      <p class="text-lg font-semibold text-slate-700">没有对应的权限</p>
      <p class="mt-2 text-sm text-slate-500">
        当前角色未被授予「运行指标查看」（view_metrics）权限。<br />
        该页面仅对开发者（developer）角色开放；如需访问，请联系系统管理员调整角色授权。
      </p>
    </div>
    <p v-else-if="error" class="text-red-600">{{ error }}</p>

    <template v-else>
      <!-- 导出链路健康度 -->
      <h2 class="text-sm font-semibold text-slate-500 uppercase tracking-wide mb-3">导出链路健康度</h2>
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 mb-8">
        <div v-for="c in CARDS" :key="c.key" class="bg-white rounded-xl shadow p-5">
          <div class="flex items-baseline justify-between">
            <span class="text-sm text-slate-500">{{ c.label }}</span>
            <span
              class="text-3xl font-bold"
              :class="c.danger && data.drops[c.key] > 0 ? 'text-red-600' : 'text-slate-800'"
            >{{ data.drops[c.key] }}</span>
          </div>
          <p class="mt-2 text-xs text-slate-400 leading-relaxed">{{ c.desc }}</p>
          <p v-if="c.danger && data.drops[c.key] > 0"
            class="mt-2 text-xs font-semibold text-red-600">⚠ 需要立即排查</p>
        </div>
      </div>

      <!-- 审计域库存 -->
      <h2 class="text-sm font-semibold text-slate-500 uppercase tracking-wide mb-3">审计域库存</h2>
      <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <div class="bg-white rounded-xl shadow p-5">
          <p class="text-sm text-slate-500">密文实体总数</p>
          <p class="text-3xl font-bold text-slate-800 mt-1">{{ inv("vault_entities") }}</p>
          <p class="mt-2 text-xs text-slate-400">密文表 entity_ciphertext 行数</p>
        </div>
        <div class="bg-white rounded-xl shadow p-5">
          <p class="text-sm text-slate-500">审计日志条数</p>
          <p class="text-3xl font-bold text-slate-800 mt-1">{{ inv("audit_entries") }}</p>
          <p class="mt-2 text-xs text-slate-400">append-only 哈希链记录总数</p>
        </div>
        <div class="bg-white rounded-xl shadow p-5">
          <p class="text-sm text-slate-500">会话数</p>
          <p class="text-3xl font-bold text-slate-800 mt-1">{{ inv("sessions") }}</p>
          <p class="mt-2 text-xs text-slate-400">已进入审计面的 conversation 数</p>
        </div>
        <div class="bg-white rounded-xl shadow p-5">
          <p class="text-sm text-slate-500">trace 数</p>
          <p class="text-3xl font-bold text-slate-800 mt-1">{{ inv("traces") }}</p>
          <p class="mt-2 text-xs text-slate-400">累计用户请求记录数</p>
        </div>
      </div>

      <!-- 还原流程 -->
      <h2 class="text-sm font-semibold text-slate-500 uppercase tracking-wide mb-3">还原流程</h2>
      <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <div v-for="(label, status) in STATUS_LABELS" :key="status" class="bg-white rounded-xl shadow p-5">
          <p class="text-sm text-slate-500">{{ label }}</p>
          <p class="text-3xl font-bold text-slate-800 mt-1">
            {{ data.inventory?.restore_requests?.[status] ?? "—" }}
          </p>
          <p class="mt-2 text-xs text-slate-400">restore_request / {{ status }}</p>
        </div>
      </div>

      <!-- 合规配置 -->
      <h2 class="text-sm font-semibold text-slate-500 uppercase tracking-wide mb-3">合规配置（当前生效值）</h2>
      <div class="bg-white rounded-xl shadow overflow-hidden mb-4">
        <table class="w-full text-sm">
          <tbody class="divide-y divide-slate-100">
            <tr v-for="(label, key) in CONFIG_LABELS" :key="key">
              <td class="px-4 py-2.5 text-slate-500 w-72">{{ label }}</td>
              <td class="px-4 py-2.5 font-mono text-xs">{{ data.config?.[key] }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p class="text-xs text-slate-400">以上阈值由环境变量配置（AUDIT_REVEAL_TTL_MINUTES 等），调整需合规确认。</p>
    </template>
  </div>
</template>
