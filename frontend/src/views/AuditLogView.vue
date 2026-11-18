<script setup>
import { ref, computed, onMounted } from 'vue'
import { api } from '../api'
import { auth } from '../store'

const loading = ref(true)
const entries = ref([])
const total = ref(0)
const page = ref(1)
const totalPages = ref(1)
const maxVisible = ref(200)
const verification = ref(null)
const zoneLabel = ref('CST+08:00')

const q = ref('')
const range = ref(null)
const role = ref('')
const action = ref('')

const fromTs = computed(() => (range.value?.[0] ?? ''))
const toTs = computed(() => (range.value?.[1] ?? ''))

async function load() {
  loading.value = true
  try {
    const data = await api.auditLog({
      page: page.value,
      q: q.value,
      from_ts: fromTs.value,
      to_ts: toTs.value,
      role: role.value,
      action: action.value
    })
    entries.value = data.entries ?? []
    total.value = data.total ?? 0
    totalPages.value = data.total_pages ?? 1
    page.value = data.page ?? 1
    maxVisible.value = data.max_visible ?? 200
    verification.value = data.verification ?? null
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
  role.value = ''
  action.value = ''
  page.value = 1
  load()
}

function jumpPage(n) {
  page.value = n
  load()
}

function roleTagType(role) {
  return { admin: 'success', user: 'info', service: 'warning' }[role] || 'info'
}

onMounted(() => {
  if (!auth.isAdmin) return
  load()
})
</script>

<template>
  <div class="page" v-loading="loading">
    <h1 class="page-title">审计日志</h1>
    <p class="page-sub">
      共 {{ total }} 条，显示第 {{ page }}/{{ totalPages }} 页（每页 10 条）。
      时间均为 {{ zoneLabel }}（存储使用 UTC）。日志按哈希链追加写入，任何删改都会被发现。
    </p>

    <el-card shadow="never" class="filter-card">
      <div class="filters">
        <el-input
          v-model="q"
          placeholder="账号 / 动作 / 对象"
          clearable
          style="width: 220px"
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
        <el-select v-model="role" placeholder="角色" clearable style="width: 130px">
          <el-option label="普通用户" value="user" />
          <el-option label="管理员" value="admin" />
          <el-option label="服务" value="service" />
        </el-select>
        <el-input
          v-model="action"
          placeholder="如 ADMIN_LOGIN"
          clearable
          style="width: 170px"
          @keyup.enter="search"
        />
        <el-button type="primary" @click="search">搜索</el-button>
        <el-button @click="reset">重置</el-button>
      </div>
    </el-card>

    <el-alert
      v-if="verification"
      :type="verification.ok ? 'success' : 'error'"
      :closable="false"
      show-icon
      class="chain-alert"
      :title="verification.ok ? '哈希链完整' : `哈希链异常（第 ${verification.first_bad_seq} 条）`"
      :description="`共校验 ${verification.entries} 条记录`"
    />

    <el-table :data="entries" stripe class="log-table">
      <el-table-column label="时间" min-width="170">
        <template #default="{ row }">
          <span class="mono text-secondary">{{ row.ts }}</span>
        </template>
      </el-table-column>
      <el-table-column label="账号" min-width="140">
        <template #default="{ row }">
          <span class="mono">{{ row.actor }}</span>
        </template>
      </el-table-column>
      <el-table-column label="角色" width="110">
        <template #default="{ row }">
          <el-tag size="small" :type="roleTagType(row.role)">{{ row.role_label }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="动作" min-width="160">
        <template #default="{ row }">
          <span class="mono">{{ row.action }}</span>
        </template>
      </el-table-column>
      <el-table-column label="对象" min-width="150">
        <template #default="{ row }">
          <div class="small text-secondary">{{ row.object_type || '-' }}</div>
          <span class="mono small">{{ row.object_id || '' }}</span>
        </template>
      </el-table-column>
      <el-table-column label="详情" min-width="260">
        <template #default="{ row }">
          <span v-if="row.detail" class="mono detail">{{ row.detail }}</span>
          <span v-else class="text-muted">-</span>
        </template>
      </el-table-column>
    </el-table>

    <div class="pager-wrap">
      <el-pagination
        v-model:current-page="page"
        :total="total"
        :page-size="10"
        layout="prev, pager, next, jumper"
        background
        @current-change="jumpPage"
      />
    </div>
  </div>
</template>

<style scoped>
.filter-card { margin-bottom: 16px; }
.filters { display: flex; gap: 12px; align-items: flex-end; flex-wrap: wrap; }
.chain-alert { margin-bottom: 16px; }
.log-table { --el-table-row-hover-bg-color: #f8fafc; }
.mono { font-family: ui-monospace, Consolas, monospace; font-size: 0.9em; }
.small { font-size: 12.5px; }
.text-secondary { color: #64748b; }
.text-muted { color: #94a3b8; }
.detail { word-break: break-all; color: #475569; font-size: 12px; }
.pager-wrap { display: flex; justify-content: center; margin-top: 20px; }
</style>
