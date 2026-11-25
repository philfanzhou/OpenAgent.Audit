<script setup>
import { ref, computed, onMounted, watch } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import { auth, setPrincipal } from '../store'
import { parseEntSegments } from '../entmark'

const route = useRoute()
// 会话 id 取响应式的路由参数：同一组件在不同会话间切换时也会重新加载。
const sessionId = computed(() => route.params.id)

const loading = ref(true)
const error = ref('')
const traces = ref([])
const zoneLabel = ref('CST+08:00')

// 脱敏芯片：管理员可查看原文；普通用户点击给提示。
const revealed = ref({}) // entityId -> plaintext

const revealable = computed(() => auth.isAdmin)

async function load() {
  loading.value = true
  error.value = ''
  const id = sessionId.value
  traces.value = []
  try {
    const data = await api.session(id)
    if (id !== sessionId.value) return // 已切换到别的会话
    traces.value = data.traces ?? []
  } catch (err) {
    if (id === sessionId.value) error.value = err.message || '加载会话失败'
  } finally {
    if (id === sessionId.value) loading.value = false
  }
}

async function reveal(entityId) {
  const result = await api.reveal(entityId)
  revealed.value = { ...revealed.value, [entityId]: result.plaintext }
}

async function onChipClick(segment) {
  if (!auth.isAdmin) {
    ElMessage.info('查看原文需要登录管理员（每次查看都会记录审计日志）')
    return
  }
  try {
    await reveal(segment.entityId)
  } catch (err) {
    ElMessage.error(err.message || '无法查看原文')
  }
}

onMounted(load)
watch(sessionId, () => {
  revealed.value = {}
  load()
})
</script>

<template>
  <div class="page" v-loading="loading">
    <h1 class="page-title">会话 <span class="mono">{{ sessionId }}</span></h1>
    <p class="page-sub">
      敏感值以「编号 + 掩码」入库。
      <template v-if="revealable">
        点击脱敏芯片可查看原文，<strong>每次查看都会记录到审计日志</strong>。
      </template>
      <template v-else>
        查看原文请先「登录管理员」。
      </template>
    </p>

    <router-link class="back-link" to="/sessions">← 返回会话列表</router-link>

    <el-alert v-if="error" type="error" :title="error" class="mt-3" :closable="false" />

    <el-empty v-else-if="!loading && !traces.length" description="该会话没有 trace 记录" />

    <el-card
      v-for="t in traces"
      :key="t.trace_id"
      shadow="never"
      class="trace-card"
    >
      <template #header>
        <span class="pill b3 obs-tag">trace</span>
        <span class="mono">{{ t.trace_id }}</span>
        <span class="text-secondary small ms-2">{{ t.timestamp }}</span>
      </template>

      <p class="meta-line">
        用户 <span class="mono">{{ t.user_id }}</span>
        <template v-if="t.agent_tag">
          · Agent <el-tag size="small" effect="plain" type="primary">{{ t.agent_tag }}</el-tag>
        </template>
        · {{ t.name }}
      </p>

      <div v-for="o in t.observations" :key="o.id || o.name" class="observation">
        <p class="obs-head">
          <span class="obs-kind-label">{{ o.type }}</span>
          <span class="obs-name">{{ o.name }}</span>
          <span v-if="o.latency_ms" class="text-secondary small">{{ o.latency_ms }}ms</span>
        </p>

        <!-- 用户输入：蓝色系 -->
        <div v-if="o.input" class="msg msg-user">
          <div class="msg-label label-user">用户</div>
          <div class="msg-body">
            <template v-for="(seg, idx) in parseEntSegments(o.input)" :key="'i' + idx">
              <span v-if="seg.type === 'text'">{{ seg.text }}</span>
              <span v-else-if="revealed[seg.entityId]" class="ent-revealed">{{ revealed[seg.entityId] }}</span>
              <button
                v-else
                class="ent-chip"
                :title="seg.entityType"
                @click="onChipClick(seg)"
              >
                {{ seg.mask }}
              </button>
            </template>
          </div>
        </div>

        <!-- 模型回复：紫色系 -->
        <div v-if="o.output" class="msg msg-agent">
          <div class="msg-label label-agent">模型</div>
          <div class="msg-body">
            <template v-for="(seg, idx) in parseEntSegments(o.output)" :key="'o' + idx">
              <span v-if="seg.type === 'text'">{{ seg.text }}</span>
              <span v-else-if="revealed[seg.entityId]" class="ent-revealed">{{ revealed[seg.entityId] }}</span>
              <button
                v-else
                class="ent-chip"
                :title="seg.entityType"
                @click="onChipClick(seg)"
              >
                {{ seg.mask }}
              </button>
            </template>
          </div>
        </div>
      </div>
    </el-card>
  </div>
</template>

<style scoped>
.page-title .mono { font-size: 20px; }
.mono { font-family: ui-monospace, Consolas, monospace; font-size: 0.92em; }
.meta-line { color: #475569; font-size: 13px; margin: 0 0 6px; }
.obs-head { margin: 16px 0 8px; display: flex; align-items: center; gap: 8px; }
.obs-kind-label { font-size: 11.5px; font-weight: 600; color: #94a3b8;
  text-transform: uppercase; letter-spacing: 0.04em; }
.obs-name { font-size: 13.5px; font-weight: 600; color: #1e293b; }
.obs-tag { margin-right: 8px; }
.text-secondary { color: #94a3b8; font-size: 12.5px; }
.ms-2 { margin-left: 8px; }
.mt-3 { margin-top: 12px; }
.pill.b3 { background: #eef2ff; color: #4f46e5; }
.pill { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 11.5px; font-weight: 600; }
.pill.tool { background: #eef2ff; color: #4f46e5; }

/* ── 用户/模型卡片区分：左侧色条 + 标签 ── */
.observation { margin-bottom: 4px; }
.msg { position: relative; padding-left: 18px; }
.msg::before { content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 4px; }
.msg-user { --chip-tint: #eff6ff; }
.msg-user::before { background: #3b82f6; }
.msg-agent { --chip-tint: #f5f3ff; }
.msg-agent::before { background: #8b5cf6; }
.msg-user .msg-body { background: var(--chip-tint, #eff6ff); }
.msg-agent .msg-body { background: var(--chip-tint, #f5f3ff); }
.msg-label {
  position: absolute; top: 6px; right: 10px;
  font-size: 11px; font-weight: 600; letter-spacing: 0.04em;
}
.label-user { color: #2563eb; }
.label-agent { color: #7c3aed; }
.msg-user { padding-left: 18px; }
.msg-body { font-family: inherit; }
</style>
