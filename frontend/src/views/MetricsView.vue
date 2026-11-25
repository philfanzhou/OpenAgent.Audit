<script setup>
import { ref, computed, onMounted } from 'vue'
import { api } from '../api'
import { auth } from '../store'

const data = ref(null)
const error = ref('')
const denied = ref(false)
const loading = ref(true)

async function load() {
  loading.value = true
  denied.value = !auth.isAdmin
  if (denied.value) {
    loading.value = false
    return
  }
  try {
    data.value = await api.metrics()
  } catch (e) {
    if (e.status === 403) denied.value = true
    else error.value = e.message || '加载失败'
  } finally {
    loading.value = false
  }
}
onMounted(load)

// 导出链路健康度：前两项 > 0 必须排查（丢弃 = 可观测性丢失，不是明文泄漏）
const CARDS = [
  { key: 'dropped_batches', label: '导出丢弃批次', danger: true,
    desc: '脱敏钩子异常时整批丢弃（fail-closed），大于 0 必须告警排查' },
  { key: 'vault_write_failures', label: '密文写库失败', danger: true,
    desc: '密文表写入重试后仍失败，对应实体将无法还原' },
  { key: 'hook_failures', label: '钩子异常次数', desc: 'mask_otel_spans 抛异常的总次数' },
  { key: 'spans_patched', label: '已脱敏 span 数', desc: '导出线程成功改写的 span 总数' },
  { key: 'entities_masked', label: '已脱敏实体数', desc: '识别并生成「编号+掩码+密文」的实体总数' },
  { key: 'restores_revealed', label: '还原查看次数', desc: '管理员查看原文的总次数（均留痕）' },
]

const INVENTORY = [
  { key: 'vault_entities', label: '密文实体总数', desc: '密文表 entity_ciphertext 行数' },
  { key: 'audit_entries', label: '审计日志条数', desc: 'append-only 哈希链记录总数' },
  { key: 'sessions', label: '会话数', desc: '已进入审计面的 conversation 数' },
  { key: 'traces', label: 'trace 数', desc: '累计用户请求记录数' },
]

const CONFIG_LABELS = {
  reveal_ttl_minutes: '还原查看窗口（分钟）',
  trace_retention_days: 'trace 保留期（天）',
  audit_archive_after_days: '审计日志归档阈值（天）',
  trace_store: 'trace 数据源',
  pii_backend: 'PII 识别后端',
  admin_session_minutes: '管理员解锁有效期（分钟）',
}

const hasDanger = computed(() =>
  CARDS.some((c) => c.danger && (data.value?.drops?.[c.key] ?? 0) > 0)
)

function drop(key) {
  const v = data.value?.drops?.[key]
  return v === null || v === undefined ? '—' : v
}
function inv(key) {
  const v = data.value?.inventory?.[key]
  return v === null || v === undefined ? '—' : v
}
</script>

<template>
  <div class="page" v-loading="loading">
    <h1 class="page-title">运行指标</h1>
    <p class="page-sub">
      导出链路的丢弃/脱敏计数（进程启动以来累计，重启后清零）与审计域库存。
    </p>

    <el-alert
      v-if="denied"
      type="warning"
      :closable="false"
      show-icon
      title="没有对应的权限"
      description="运行指标仅管理员可见。请先在右上角「登录管理员」。"
    />
    <el-alert
      v-else-if="error"
      type="error"
      :closable="false"
      show-icon
      :title="error"
    />
    <template v-else-if="data">
      <el-alert
        v-if="hasDanger"
        type="error"
        :closable="false"
        show-icon
        class="chain-alert"
        title="⚠ 需要立即排查：导出链路出现丢弃或密文写入失败"
      />

      <h2 class="section-title">导出链路健康度</h2>
      <div class="card-grid cols-3">
        <el-card v-for="c in CARDS" :key="c.key" shadow="never" class="metric-card">
          <div class="metric-head">
            <span class="metric-label">{{ c.label }}</span>
          </div>
          <p class="metric-value" :class="{ danger: c.danger && drop(c.key) > 0 }">{{ drop(c.key) }}</p>
          <p class="metric-desc">{{ c.desc }}</p>
        </el-card>
      </div>

      <h2 class="section-title">审计域库存</h2>
      <div class="card-grid cols-4">
        <el-card v-for="c in INVENTORY" :key="c.key" shadow="never" class="metric-card">
          <p class="metric-label">{{ c.label }}</p>
          <p class="metric-value">{{ inv(c.key) }}</p>
          <p class="metric-desc">{{ c.desc }}</p>
        </el-card>
      </div>

      <h2 class="section-title">合规配置（当前生效值）</h2>
      <el-card shadow="never">
        <el-table :data="Object.keys(CONFIG_LABELS).map((k) => ({ key: k, label: CONFIG_LABELS[k], value: data.config?.[k] }))">
          <el-table-column prop="label" label="配置项" min-width="220" />
          <el-table-column prop="value" label="生效值" min-width="160">
            <template #default="{ row }"><span class="mono">{{ row.value ?? '—' }}</span></template>
          </el-table-column>
        </el-table>
      </el-card>
      <p class="page-sub metrics-note">以上阈值由环境变量配置（AUDIT_REVEAL_TTL_MINUTES 等），调整需合规确认。</p>
    </template>
  </div>
</template>

<style scoped>
.section-title { font-size: 13px; font-weight: 600; color: #64748b; letter-spacing: 0.02em; margin: 24px 0 12px; }
.card-grid { display: grid; gap: 12px; }
.card-grid.cols-3 { grid-template-columns: repeat(3, minmax(0, 1fr)); }
.card-grid.cols-4 { grid-template-columns: repeat(4, minmax(0, 1fr)); }
@media (max-width: 900px) { .card-grid.cols-3, .card-grid.cols-4 { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
.metric-card :deep(.el-card__body) { padding: 14px 18px; }
.metric-label { font-size: 13px; color: #64748b; margin: 0; }
.metric-value { font-size: 26px; font-weight: 650; color: #1e293b; margin: 4px 0 6px; line-height: 1.2; }
.metric-value.danger { color: #dc2626; }
.metric-desc { font-size: 12px; color: #94a3b8; margin: 0; line-height: 1.5; }
.metrics-note { margin: 12px 0 0; }
</style>
