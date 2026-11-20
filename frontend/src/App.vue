<script setup lang="ts">
import { onMounted } from 'vue'
import NavBar from '@/components/NavBar.vue'
import { fetchHealthMeta } from '@/services/labState'

onMounted(() => {
  void fetchHealthMeta()
})
</script>

<template>
  <div class="min-h-screen bg-[#060a12] text-slate-100">
    <NavBar />
    <main>
      <router-view />
    </main>
    <footer class="mx-auto mt-10 max-w-7xl border-t border-slate-900 px-4 py-6 text-center text-[11px] text-slate-500">
      AntiCrawl Lab · 仅限本地隔离安全研究与教学使用（默认监听 127.0.0.1，采集数据仅本地 SQLite 留存）
    </footer>
  </div>
</template>
