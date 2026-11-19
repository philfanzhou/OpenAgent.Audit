<script setup>
import { ref, computed, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { useRouter } from 'vue-router'
import { api } from '../api'

const router = useRouter()
const loading = ref(true)
const sessions = ref([])
const total = ref(0)
const page = ref(1)
const totalPages = ref(1)
const browseBlocked = ref(false)
const maxVisible = ref(200)
const zoneLabel = ref('CST+08:00')

const q = ref('')
const range = ref(null) // [start, end] 来自日期范围选择器
const agent = ref('')
const jumpTo = ref('')

const fromTs = computed(() => (range.value?.[0] ?? ''))
const toTs = computed(() => (range.value?.[1] ?? ''))

async function load() {
  loading.value = true
  try {
    const data = await api.sessions({
      page: page.value,
      q: q.value,
      from_ts: fromTs.value,
      to_ts: toTs.value,
      agent: agent.value
    })
    sessions.value = data.sessions ?? []
    total.value = data.total ?? 0
    totalPages.value = data.total_pages ?? 1
    page.value = data.page ?? 1
    browseBlocked.value = data.browse_blocked ?? false
    maxVisible.value = data.browse_threshold ?? 200
    zoneLabel.value = data.display_zone_label ?? zoneLabel.value
  } finally {
    loading.value = false
  }
}

function search() {
  page.value = 1
  load()
}

function reset() {
  q.value = ''
  range.value = null
  agent.value = ''
  page.value = 1
  load()
}

function jump() {
  const n = parseInt(jumpTo.value, 10)
  if (!n || n < 1 || n > totalPages.value) {
    ElMessage.warning(`请输入 1 ~ ${totalPages.value} 之间的页码`)
    return
  }
  jumpTo.value = ''
  page.value = n
  load()
}

function openSession(id) {
  // 用户正在选中文本（复制用户/Agent 数据）时不触发跳转。
  const selection = window.getSelection()
  if (selection && selection.toString().length > 0) return
  // SPA 内部路由：不整页刷新，切换毫秒级完成。
  router.push(`/sessions/${id}`)
}

onMounted(load)
</script>

<template>
  <div class="page">
    <h1 class="page-title">会话</h1>
    <p class="page-sub">
      共 {{ total }} 个会话，显示第 {{ page }}/{{ totalPages }} 页（每页 10 条）。
      时间均为 {{ zoneLabel }}。搜索可查找更早的数据。
    </p>

    <el-card shadow="never" class="filter-card">
      <div class="filters">
        <el-input
          v-model="q"
          placeholder="会话编号 / 用户 / Agent"
          clearable
          style="width: 230px"
          @keyup.enter="search"
        />
        <el-date-picker
          v-model="range"
          type="datetimerange"
          range-separator="至"
          start-placeholder="开始时间"
          end-placeholder="结束时间"
          value-format="YYYY-MM-DDTHH:mm:ss"
          style="width: 340px"
        />
        <el-input
          v-model="agent"
          placeholder="如 cs-bot"
          clearable
          style="width: 160px"
          @keyup.enter="search"
        />
        <el-button type="primary" @click="search">搜索</el-button>
        <el-button @click="reset">重置</el-button>
      </div>
    </el-card>

    <el-table
      v-loading="loading"
      :data="sessions"
      stripe
      class="sessions-table"
      @row-click="(row) => openSession(row.session_id)"
    >
      <el-table-column label="会话" min-width="230">
        <template #default="{ row }">
          <el-link type="primary" @click.stop="openSession(row.session_id)">
            <span class="mono">{{ row.session_id }}</span>
          </el-link>
        </template>
      </el-table-column>
      <el-table-column label="用户" min-width="210">
        <template #default="{ row }">
          <span class="mono">{{ row.user_id || '-' }}</span>
        </template>
      </el-table-column>
      <el-table-column label="Agent" min-width="170">
        <template #default="{ row }">
          <el-tag
            v-for="t in row.agent_tags || []"
            :key="t"
            size="small"
            effect="plain"
            class="agent-tag"
          >
            {{ t }}
          </el-tag>
          <span v-if="!(row.agent_tags || []).length" class="text-muted">-</span>
        </template>
      </el-table-column>
      <el-table-column prop="trace_count" label="条目" width="80" />
      <el-table-column label="最近活动" min-width="190">
        <template #default="{ row }">
          <span class="text-secondary">{{ row.last_ts }}</span>
        </template>
      </el-table-column>
    </el-table>

    <div class="pager-wrap">
      <el-pagination
        v-model:current-page="page"
        :total="total"
        :page-size="10"
        layout="prev, pager, next"
        background
        @current-change="load"
      />
      <form class="jump-form" @submit.prevent="jump">
        <span class="jump-label">跳至第</span>
        <el-input v-model="jumpTo" class="jump-input" placeholder="页码" @keyup.enter="jump" />
        <span class="jump-label">页</span>
        <el-button type="primary" plain size="small" native-type="submit">跳转</el-button>
      </form>
    </div>

    <el-alert
      v-if="browseBlocked"
      type="warning"
      :closable="false"
      show-icon
      class="blocked-alert"
      :title="`会话数量（${total}）超过 ${maxVisible} 条，请用搜索条件缩小范围`"
    />
  </div>
</template>

<style scoped>
.filter-card { margin-bottom: 16px; }
.filters { display: flex; gap: 12px; align-items: flex-end; flex-wrap: wrap; }
.sessions-table { --el-table-row-hover-bg-color: #f8fafc; }
.agent-tag { margin-right: 4px; }
.text-muted { color: #94a3b8; }
.text-secondary { color: #64748b; font-size: 13px; }
.mono { font-family: ui-monospace, Consolas, monospace; font-size: 0.9em; }
.pager-wrap { display: flex; justify-content: center; align-items: center;
  gap: 10px; margin-top: 20px; }
.jump-form { display: flex; align-items: center; gap: 4px; }
.jump-label { font-size: 13px; color: #475569; }
.jump-input { width: 64px; }
.jump-input :deep(.el-input__inner) { text-align: center; }
.blocked-alert { margin-top: 12px; }
</style>
