import { defineStore } from 'pinia'
import { ref } from 'vue'
import axios from 'axios'
import type { AnalysisResult, AnomalyRule, ApplyMode } from '@/types'

export const LOG_TYPES = ['nginx', 'apache', 'json_app', 'custom']

export const RULE_FIELDS = {
  windowSize: { label: '判定窗口（条/窗口）', min: 1, max: 5000 },
  errorLimit: { label: '高频错误条数上限', min: 0, max: 5000 },
  volumeLimit: { label: '窗口日志量上限', min: 1, max: 5000 },
  consecutiveLimit: { label: '连续超限次数', min: 1, max: 100 }
} as const

export type RuleField = keyof typeof RULE_FIELDS

/** 与后端一致的校验：为空/非整数/越界/上限填反/空词表均不合格 */
export function validateRule(rule: AnomalyRule): Partial<Record<RuleField | 'keywords', string>> {
  const errors: Partial<Record<RuleField | 'keywords', string>> = {}
  const intField = (v: unknown): v is number =>
    typeof v === 'number' && Number.isInteger(v)
  if (!intField(rule.windowSize) || rule.windowSize < 1 || rule.windowSize > 5000)
    errors.windowSize = '需为 1-5000 的整数，不能为空'
  if (!intField(rule.consecutiveLimit) || rule.consecutiveLimit < 1 || rule.consecutiveLimit > 100)
    errors.consecutiveLimit = '需为 1-100 的整数，不能为空'
  if (!intField(rule.errorLimit) || rule.errorLimit < 0)
    errors.errorLimit = '需为不小于 0 的整数，不能为空'
  if (!intField(rule.volumeLimit) || rule.volumeLimit < 1)
    errors.volumeLimit = '需为不小于 1 的整数，不能为空'
  if (!errors.errorLimit && !errors.volumeLimit && rule.errorLimit > rule.volumeLimit)
    errors.errorLimit = `不能高于窗口日志量上限(${rule.volumeLimit})，上限填反`
  if (!errors.volumeLimit && !errors.windowSize && rule.volumeLimit > rule.windowSize)
    errors.volumeLimit = `不能高于判定窗口大小(${rule.windowSize})，上限填反`
  if (!Array.isArray(rule.keywords) || rule.keywords.length === 0)
    errors.keywords = '词表不能为空，每行一个关键词'
  else if (rule.keywords.some(k => !k.trim()))
    errors.keywords = '词表不能包含空行'
  else if (rule.keywords.some(k => k.length > 50))
    errors.keywords = '单个关键词不能超过 50 个字符'
  return errors
}

function defaultRules(): Record<string, AnomalyRule> {
  const base: AnomalyRule = {
    windowSize: 20, errorLimit: 5, volumeLimit: 20, consecutiveLimit: 1,
    keywords: ['timeout', 'failed', 'error', 'exception', 'unavailable', 'oom']
  }
  return Object.fromEntries(LOG_TYPES.map(t => [t, { ...base, keywords: [...base.keywords] }]))
}

export const useLogStore = defineStore('log', () => {
  const result = ref<AnalysisResult | null>(null)
  const loading = ref(false)
  const searchQuery = ref('')
  const logType = ref('nginx')
  // 各日志类型独立的判定口径，从后端加载，重启服务后沿用
  const rules = ref<Record<string, AnomalyRule>>(defaultRules())
  const applyMode = ref<ApplyMode>('new_only')
  const rulesLoaded = ref(false)

  async function loadRules() {
    const { data } = await axios.get('/api/rules')
    rules.value = data.rules
    applyMode.value = data.applyMode
    rulesLoaded.value = true
  }

  async function generate() {
    loading.value = true
    try {
      const { data } = await axios.post('/api/generate', { type: logType.value, count: 1000 })
      result.value = data
    } finally { loading.value = false }
  }

  async function detect() {
    if (!result.value) return
    loading.value = true
    try {
      const { data } = await axios.post('/api/detect', {
        type: logType.value, logs: null, query: searchQuery.value
      })
      result.value = data
    } finally { loading.value = false }
  }

  /** 保存某日志类型的规则；recompute 模式下后端会同时返回重算结果 */
  async function saveRule(type: string, rule: AnomalyRule, mode: ApplyMode) {
    const { data } = await axios.put(`/api/rules/${type}`, { rule, applyMode: mode })
    rules.value = data.rules
    applyMode.value = data.applyMode
    // 当前展示的就是该日志类型时，直接采用重算结果，保证各面板同口径
    if (data.recomputed && data.result && type === logType.value)
      result.value = data.result
    return data as { recomputed: boolean; result: AnalysisResult | null }
  }

  async function setApplyMode(mode: ApplyMode) {
    const { data } = await axios.put('/api/settings/apply-mode', { applyMode: mode })
    applyMode.value = data.applyMode
  }

  return {
    result, loading, searchQuery, logType, rules, applyMode, rulesLoaded,
    loadRules, generate, detect, saveRule, setApplyMode
  }
})
