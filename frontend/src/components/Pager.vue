<script setup>
import { computed } from "vue";

const props = defineProps({
  page: { type: Number, required: true },
  pageSize: { type: Number, required: true },
  total: { type: Number, required: true },
});
const emit = defineEmits(["change"]);

const pages = computed(() => Math.max(1, Math.ceil(props.total / props.pageSize)));

function go(p) {
  if (p < 1 || p > pages.value || p === props.page) return;
  emit("change", p);
}

// page numbers around the current one, with fixed first/last
const visible = computed(() => {
  const out = [];
  const from = Math.max(1, props.page - 2);
  const to = Math.min(pages.value, props.page + 2);
  for (let p = from; p <= to; p++) out.push(p);
  return out;
});
</script>

<template>
  <div class="flex items-center justify-between mt-4 text-sm" v-if="total > 0">
    <span class="text-slate-500">
      共 <span class="font-semibold text-slate-700">{{ total }}</span> 条 ·
      第 {{ page }} / {{ pages }} 页（每页 {{ pageSize }} 条）
    </span>
    <div class="flex items-center gap-1">
      <button @click="go(page - 1)" :disabled="page <= 1"
        class="px-2.5 py-1 rounded border border-slate-200 hover:bg-slate-50 disabled:opacity-40 disabled:cursor-not-allowed">上一页</button>
      <button v-if="visible[0] > 1" @click="go(1)"
        class="px-2.5 py-1 rounded border border-slate-200 hover:bg-slate-50">1</button>
      <span v-if="visible[0] > 2" class="px-1 text-slate-400">…</span>
      <button v-for="p in visible" :key="p" @click="go(p)"
        class="px-2.5 py-1 rounded border"
        :class="p === page ? 'bg-blue-600 text-white border-blue-600' : 'border-slate-200 hover:bg-slate-50'">{{ p }}</button>
      <span v-if="visible[visible.length - 1] < pages - 1" class="px-1 text-slate-400">…</span>
      <button v-if="visible[visible.length - 1] < pages" @click="go(pages)"
        class="px-2.5 py-1 rounded border border-slate-200 hover:bg-slate-50">{{ pages }}</button>
      <button @click="go(page + 1)" :disabled="page >= pages"
        class="px-2.5 py-1 rounded border border-slate-200 hover:bg-slate-50 disabled:opacity-40 disabled:cursor-not-allowed">下一页</button>
    </div>
  </div>
</template>
