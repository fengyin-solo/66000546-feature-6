<template>
  <div class="panel">
    <h4>🚨 告警列表</h4>
    <div v-if="cfg" class="criteria">
      当前口径[{{ store.result?.logType }}]：窗口{{ cfg.windowSize }}条 · ERROR上限{{ cfg.errorThreshold }} ·
      日志量[{{ cfg.countMin }}, {{ cfg.countMax }}] · 关键词{{ cfg.keywords.length }}个 · 连续{{ cfg.consecutive }}次超限告警
    </div>
    <div v-if="!alerts.length" class="empty">暂无告警</div>
    <div v-for="a in alerts.slice(0,8)" :key="a.id" class="alert-row" :class="a.severity">
      <span class="a-sev" :class="a.severity">{{ a.severity.toUpperCase() }}</span>
      <span class="a-msg">{{ a.message }}</span>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useLogStore } from '../store/log'
const store = useLogStore()
const alerts = computed(() => store.result?.alerts || [])
const cfg = computed(() => store.result?.appliedConfig)
</script>

<style scoped>
.panel{background:#1e293b;border-radius:8px;padding:12px;border:1px solid #334155;margin-top:12px}
.panel h4{color:#f87171;font-size:13px;margin-bottom:8px}
.criteria{font-size:10px;color:#64748b;margin-bottom:8px;line-height:1.5}
.empty{color:#64748b;font-size:12px}
.alert-row{display:flex;gap:8px;padding:4px 6px;margin:2px 0;border-radius:4px;font-size:11px;align-items:flex-start}
.alert-row.high{background:#7f1d1d33}
.alert-row.critical{background:#991b1b55}
.alert-row.medium{background:#78350f33}
.a-sev{font-weight:700;min-width:50px;font-size:10px;padding:1px 4px;border-radius:2px}
.a-sev.critical{color:#fca5a5;background:#991b1b}
.a-sev.high{color:#f87171;background:#7f1d1d}
.a-sev.medium{color:#fbbf24;background:#78350f}
.a-msg{color:#e2e8f0}
</style>