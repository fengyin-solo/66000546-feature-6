<template>
  <div class="app-root">
    <header class="top-bar">
      <h1>📊 分布式日志聚合与智能异常检测平台</h1>
      <div class="toolbar">
        <el-select v-model="store.logType" size="small" style="width:140px">
          <el-option v-for="t in LOG_TYPES" :key="t" :label="t" :value="t"/>
        </el-select>
        <el-input v-model="store.searchQuery" placeholder="搜索关键词..." size="small" style="width:200px" clearable
                  @keyup.enter="store.detect()"/>
        <el-button size="small" @click="ruleDialog?.open()">⚙ 判定规则</el-button>
        <el-button size="small" @click="store.generate()" :loading="store.loading">🔍 生成日志</el-button>
        <el-button size="small" type="warning" @click="store.detect()" :disabled="!store.result">⚠ 检测异常</el-button>
      </div>
    </header>
    <div class="rule-strip" v-if="store.result?.appliedRule">
      <span class="strip-label">{{ store.logType }} 当前判定口径：</span>
      <el-tag size="small" type="info">窗口 {{ store.result.appliedRule.windowSize }} 条</el-tag>
      <el-tag size="small" type="danger">错误上限 {{ store.result.appliedRule.errorLimit }}</el-tag>
      <el-tag size="small" type="warning">流量上限 {{ store.result.appliedRule.volumeLimit }}</el-tag>
      <el-tag size="small">连续超限 {{ store.result.appliedRule.consecutiveLimit }} 次</el-tag>
      <el-tag size="small" type="success">关键词 {{ store.result.appliedRule.keywords.length }} 个</el-tag>
      <el-tag size="small" :type="store.applyMode === 'recompute' ? 'warning' : 'info'">
        生效方式：{{ store.applyMode === 'recompute' ? '保存即重算已有结果' : '仅对后续日志生效' }}
      </el-tag>
    </div>
    <div class="main-grid">
      <div class="grid-col">
        <LogTable />
      </div>
      <div class="grid-col">
        <AnomalyChart />
        <AlertPanel />
      </div>
    </div>
    <div class="bottom-row">
      <TrendChart />
      <HeatmapChart />
    </div>
    <RuleSettingsDialog ref="ruleDialog"/>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import LogTable from './components/LogTable.vue'
import AnomalyChart from './components/AnomalyChart.vue'
import AlertPanel from './components/AlertPanel.vue'
import TrendChart from './components/TrendChart.vue'
import HeatmapChart from './components/HeatmapChart.vue'
import RuleSettingsDialog from './components/RuleSettingsDialog.vue'
import { useLogStore, LOG_TYPES } from './store/log'
const store = useLogStore()
const ruleDialog = ref<InstanceType<typeof RuleSettingsDialog> | null>(null)
onMounted(() => { store.loadRules() })
</script>

<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,monospace;background:#0f172a;color:#e2e8f0}
.app-root{min-height:100vh}
.top-bar{display:flex;justify-content:space-between;align-items:center;padding:10px 20px;background:#1e293b;border-bottom:1px solid #334155}
.top-bar h1{font-size:1.1rem;color:#38bdf8}
.toolbar{display:flex;gap:8px;align-items:center}
.rule-strip{display:flex;gap:6px;align-items:center;padding:6px 20px;background:#0f172a;border-bottom:1px solid #1e293b;font-size:11px;flex-wrap:wrap}
.strip-label{color:#94a3b8}
.main-grid{display:grid;grid-template-columns:1fr 400px;gap:12px;padding:12px 20px;min-height:50vh}
.grid-col{overflow:hidden}
.bottom-row{display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:0 20px 16px}
</style>
