<script setup>
import { ref, watch, onBeforeUnmount } from "vue";

const props = defineProps({
  modelValue: { type: String, default: "" },
  placeholder: { type: String, default: "搜索…" },
});
const emit = defineEmits(["update:modelValue"]);

const inner = ref(props.modelValue);
let timer = null;

watch(inner, (v) => {
  if (timer) clearTimeout(timer);
  timer = setTimeout(() => emit("update:modelValue", v.trim()), 300);
});
watch(() => props.modelValue, (v) => { inner.value = v; });
onBeforeUnmount(() => { if (timer) clearTimeout(timer); });
</script>

<template>
  <div class="relative w-72">
    <input v-model="inner" type="search" :placeholder="placeholder"
      class="w-full rounded-lg border border-slate-300 pl-8 pr-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
    <span class="absolute left-2.5 top-2 text-slate-400">🔍</span>
  </div>
</template>
