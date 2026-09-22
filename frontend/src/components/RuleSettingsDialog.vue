<template>
  <el-dialog v-model="visible" title="⚙ 异常判定规则（按日志类型分别配置）" width="640px"
             @open="onOpen">
    <el-tabs v-model="activeType">
      <el-tab-pane v-for="t in LOG_TYPES" :key="t" :label="t" :name="t">
        <div v-if="drafts[t]" class="rule-form">
          <div v-for="f in numberFields" :key="f.key" class="form-row">
            <label>{{ RULE_FIELDS[f.key].label }}</label>
            <el-input-number v-model="drafts[t]![f.key]" :min="f.min" :max="f.max" :step="1"
                             :controls="false" size="small" style="width:170px"
                             :class="{ invalid: errors[t]?.[f.key] }"/>
            <span v-if="errors[t]?.[f.key]" class="err">{{ errors[t]![f.key] }}</span>
          </div>
          <div class="form-row align-top">
            <label>关键词命中词表<br/><span class="hint">每行一个，不区分大小写</span></label>
            <div class="kw-box">
              <el-input v-model="keywordText[t]" type="textarea" :rows="5" size="small"
                        :class="{ invalid: errors[t]?.keywords }"
                        placeholder="timeout&#10;failed&#10;exception"/>
              <span v-if="errors[t]?.keywords" class="err">{{ errors[t]!.keywords }}</span>
            </div>
          </div>
          <div class="effective" v-if="appliedText[t]">
            当前结果口径：{{ appliedText[t] }}
          </div>
        </div>
      </el-tab-pane>
    </el-tabs>

    <el-divider style="margin:8px 0"/>
    <div class="apply-mode">
      <span class="mode-title">生效方式：</span>
      <el-radio-group v-model="mode" @change="onModeChange">
        <el-radio value="new_only">仅对后续生成的日志生效</el-radio>
        <el-radio value="recompute">保存时同时重算已有结果</el-radio>
      </el-radio-group>
      <div class="hint">选择会在服务重启后继续沿用；窗口等口径变化后，所有图表/告警面板按同一口径展示。</div>
    </div>

    <template #footer>
      <el-button size="small" @click="visible = false">取消</el-button>
      <el-button size="small" type="primary"
                 :disabled="hasError(activeType)"
                 :loading="saving" @click="onSave">
        保存{{ mode === 'recompute' ? '并重算' : '' }}
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { ref, reactive, computed } from 'vue'
import { ElMessage } from 'element-plus'
import axios from 'axios'
import { LOG_TYPES, RULE_FIELDS, useLogStore, validateRule, type RuleField } from '../store/log'
import type { AnomalyRule, ApplyMode } from '../types'

const store = useLogStore()
const visible = ref(false)
const activeType = ref('nginx')
const mode = ref<ApplyMode>('new_only')
const saving = ref(false)
const drafts = reactive<Record<string, AnomalyRule>>({})
const keywordText = reactive<Record<string, string>>({})

const numberFields: { key: RuleField; min: number; max: number }[] = [
  { key: 'errorLimit', min: 0, max: 5000 },
  { key: 'volumeLimit', min: 1, max: 5000 },
  { key: 'windowSize', min: RULE_FIELDS.windowSize.min, max: RULE_FIELDS.windowSize.max },
  { key: 'consecutiveLimit', min: RULE_FIELDS.consecutiveLimit.min, max: RULE_FIELDS.consecutiveLimit.max }
]

function parseKeywords(t: string): string[] {
  return keywordText[t].split('\n').map(k => k.trim()).filter(Boolean)
}

const errors = computed<Record<string, ReturnType<typeof validateRule>>>(() => {
  const out: Record<string, ReturnType<typeof validateRule>> = {}
  for (const t of LOG_TYPES) {
    if (!drafts[t]) continue
    out[t] = validateRule({ ...drafts[t], keywords: parseKeywords(t) })
  }
  return out
})

const appliedText = computed<Record<string, string>>(() => {
  const out: Record<string, string> = {}
  const r = store.result?.appliedRule
  if (r && store.result) {
    out[store.logType] = `窗口=${r.windowSize}条 / 错误上限=${r.errorLimit} / 流量上限=${r.volumeLimit}` +
      ` / 连续${r.consecutiveLimit}次 / 关键词${r.keywords.length}个`
  }
  return out
})

function hasError(t: string): boolean {
  return Object.keys(errors.value[t] || {}).length > 0
}

defineExpose({ open: () => { visible.value = true } })

function onOpen() {
  activeType.value = store.logType
  mode.value = store.applyMode
  for (const t of LOG_TYPES) {
    const r = store.rules[t]
    if (r) {
      drafts[t] = { ...r, keywords: [...r.keywords] }
      keywordText[t] = r.keywords.join('\n')
    }
  }
}

async function onModeChange() {
  // 立即持久化选择，重启服务后仍沿用
  try {
    await store.setApplyMode(mode.value)
  } catch {
    ElMessage.error('生效方式保存失败')
  }
}

async function onSave() {
  const t = activeType.value
  const rule: AnomalyRule = { ...drafts[t], keywords: parseKeywords(t) }
  const errs = validateRule(rule)
  if (Object.keys(errs).length) {
    ElMessage.error('存在不合格项，请按提示修正后再保存')
    return
  }
  saving.value = true
  try {
    const data = await store.saveRule(t, rule, mode.value)
    if (mode.value === 'recompute') {
      if (data.recomputed) {
        ElMessage.success(t === store.logType ? '已保存并按新口径重算当前结果' : `已保存并重算 ${t} 的已有结果`)
      } else {
        ElMessage.warning('已保存；该类型暂无已生成日志，将对之后生成的日志生效')
      }
    } else {
      ElMessage.success('已保存，仅对后续生成的日志生效')
    }
    visible.value = false
  } catch (e) {
    if (axios.isAxiosError(e) && e.response?.status === 422) {
      const detail = e.response.data?.detail
      const fieldErrors = detail?.errors
      ElMessage.error(detail?.message || '存在不合格项，未保存')
      if (fieldErrors) {
        const names: Record<string, string> = {
          windowSize: '判定窗口', errorLimit: '高频错误条数上限',
          volumeLimit: '窗口日志量上限', consecutiveLimit: '连续超限次数',
          keywords: '关键词词表', applyMode: '生效方式'
        }
        ElMessage.error('不合格项：' + Object.entries(fieldErrors)
          .map(([k, v]) => `${names[k] || k}：${v}`).join('；'))
      }
    } else {
      ElMessage.error('保存失败，请重试')
    }
  } finally {
    saving.value = false
  }
}
</script>

<style scoped>
.rule-form { display: flex; flex-direction: column; gap: 10px; padding-right: 8px }
.form-row { display: flex; align-items: center; gap: 10px; font-size: 12px }
.form-row label { width: 170px; color: #cbd5e1; flex-shrink: 0 }
.form-row.align-top { align-items: flex-start }
.form-row.align-top label { padding-top: 4px }
.kw-box { flex: 1 }
.hint { color: #64748b; font-size: 11px; font-weight: 400 }
.err { color: #f87171; font-size: 11px }
.invalid :deep(.el-input__wrapper), .invalid :deep(.el-textarea__inner) {
  box-shadow: 0 0 0 1px #f87171 inset !important;
}
.effective { margin-top: 4px; font-size: 11px; color: #38bdf8; background: #0f172a;
  border-radius: 4px; padding: 6px 8px }
.apply-mode { font-size: 12px }
.mode-title { color: #cbd5e1 }
</style>
