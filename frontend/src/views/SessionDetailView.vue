<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import { auth, setPrincipal } from '../store'
import { parseEntSegments } from '../entmark'

const route = useRoute()
const sessionId = route.params.id

const loading = ref(true)
const error = ref('')
const traces = ref([])
const zoneLabel = ref('CST+08:00')

// 脱敏芯片：管理员可查看原文；普通用户点击给提示。
const revealed = ref({}) // entityId -> plaintext

const revealable = computed(() => auth.isAdmin)

async function load() {
  loading.value = true
  try {
    const data = await api.session(sessionId)
    traces.value = data.traces ?? []
  } catch (err) {
    error.value = err.message
  } finally {
    loading.value = false
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
</script>

<template>
  <div class="page">
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

    <el-button size="small" @click="$router.push('/sessions')">← 返回会话列表</el-button>

    <el-alert v-if="error" type="error" :title="error" class="mt-3" :closable="false" />

    <el-empty v-else-if="!loading && !traces.length" description="该会话没有 trace 记录" />

    <el-card
      v-for="t in traces"
      :key="t.trace_id"
      shadow="never"
      class="trace-card"
      v-loading="loading"
    >
      <template #header>
        <span class="pill b3 obs-tag">trace</span>
        <span class="mono">{{ t.trace_id }}</span>
        <span class="text-secondary small ms-2">{{ t.timestamp }}</span>
      </template>

      <p class="meta-line">
        用户 <span class="mono">{{ t.user_id }}</span>
        <template v-if="t.agent_tag">
          · Agent <span class="mono">{{ t.agent_tag }}</span>
        </template>
        · {{ t.name }}
      </p>

      <div v-for="o in t.observations" :key="o.id || o.name" class="observation">
        <p class="obs-head">
          <span class="obs-kind-label">{{ o.type }}</span>
          <span class="obs-name">{{ o.name }}</span>
          <span v-if="o.latency_ms" class="text-secondary small">{{ o.latency_ms }}ms</span>
        </p>

        <template v-if="o.input">
          <div class="msg">
            <template v-for="(seg, idx) in parseEntSegments(o.input)" :key="idx">
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
        </template>

        <template v-if="o.output">
          <div class="msg">
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
        </template>
      </div>
    </el-card>
  </div>
</template>


<style scoped>
.page-title .mono { font-size: 20px; }
.mono { font-family: ui-monospace, Consolas, monospace; font-size: 0.92em; }
.meta-line { color: #475569; font-size: 13px; margin: 0 0 4px; }
.obs-head { margin: 18px 0 8px; }
.obs-head strong { font-size: 13.5px; }
.obs-tag { margin-right: 8px; }
.text-secondary { color: #94a3b8; font-size: 12.5px; }
.ms-2 { margin-left: 8px; }
.mt-3 { margin-top: 12px; }
</style>
