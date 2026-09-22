import { defineStore } from 'pinia'
import { ref } from 'vue'
import axios from 'axios'
import { ElMessage } from 'element-plus'
import type { AnalysisResult, RuleConfig, ApplyMode, ConfigResponse } from '@/types'

export interface FieldErrors { [field: string]: string }

export const useLogStore = defineStore('log', () => {
  const result = ref<AnalysisResult | null>(null)
  const loading = ref(false)
  const searchQuery = ref('')
  const logType = ref('nginx')
  const resultType = ref('nginx')          // 当前展示结果所属的日志类型
  const configs = ref<Record<string, RuleConfig>>({})
  const applyMode = ref<ApplyMode>('all')
  const limits = ref<ConfigResponse['limits']>({})
  const keywordLimits = ref<ConfigResponse['keywordLimits']>({ maxItems: 50, maxLen: 50 })
  const logTypes = ref<string[]>(['nginx', 'apache', 'json_app', 'custom'])

  async function fetchConfig() {
    const { data } = await axios.get<ConfigResponse>('/api/config')
    configs.value = data.configs
    applyMode.value = data.applyMode
    limits.value = data.limits
    keywordLimits.value = data.keywordLimits
    logTypes.value = data.logTypes
  }

  // 保存某日志类型的规则；保存失败抛出字段级错误 {field: msg}
  // 保存成功且生效范围为 all 时，按同一份口径重算已有结果
  async function saveConfig(type: string, cfg: RuleConfig): Promise<{ recomputed: boolean }> {
    try {
      const { data } = await axios.put('/api/config', { logType: type, config: cfg })
      configs.value = data.configs
      let recomputed = false
      if (applyMode.value === 'all' && result.value && type === resultType.value) {
        await detect()
        recomputed = true
      }
      return { recomputed }
    } catch (e: any) {
      const detail = e.response?.data?.detail
      if (e.response?.status === 422 && detail?.errors) throw detail.errors as FieldErrors
      throw { _global: typeof detail === 'string' ? detail : '保存失败，请稍后重试' } as FieldErrors
    }
  }

  // 生效范围选择即时持久化，重启服务后沿用上次选择
  async function setApplyMode(mode: ApplyMode) {
    const prev = applyMode.value
    applyMode.value = mode
    try {
      await axios.put('/api/apply-mode', { applyMode: mode })
    } catch (e) {
      applyMode.value = prev
      throw e
    }
  }

  async function generate() {
    loading.value = true
    try {
      const { data } = await axios.post('/api/generate', { type: logType.value, count: 1000 })
      result.value = data
      resultType.value = logType.value
    } catch (e: any) {
      ElMessage.error(e.response?.data?.detail || '生成失败，请重试')
    } finally { loading.value = false }
  }

  async function detect() {
    if (!result.value) return
    loading.value = true
    try {
      const { data } = await axios.post('/api/detect', { logType: resultType.value, query: searchQuery.value })
      result.value = data
    } catch (e: any) {
      ElMessage.error(e.response?.data?.detail || '检测失败，请重试')
    } finally { loading.value = false }
  }

  return {
    result, loading, searchQuery, logType, resultType,
    configs, applyMode, limits, keywordLimits, logTypes,
    fetchConfig, saveConfig, setApplyMode, generate, detect
  }
})
