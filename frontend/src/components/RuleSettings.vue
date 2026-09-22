<template>
  <el-dialog v-model="visible" title="⚙ 异常判定规则设置" width="580px" :close-on-click-modal="false">
    <div class="type-bar">
      <span class="lb">日志类型</span>
      <el-radio-group v-model="editType" size="small">
        <el-radio-button v-for="t in store.logTypes" :key="t" :value="t">{{ t }}</el-radio-button>
      </el-radio-group>
      <span class="hint">按类型分别配置，互不影响</span>
    </div>

    <el-form label-width="150px" size="small" class="rule-form">
      <el-form-item :label="labelOf('errorThreshold')" :error="errors.errorThreshold">
        <el-input v-model="form.errorThreshold" style="width:160px" placeholder="整数"/>
        <span class="range">{{ rangeText('errorThreshold') }}</span>
      </el-form-item>
      <el-form-item :label="labelOf('countMin')" :error="errors.countMin">
        <el-input v-model="form.countMin" style="width:160px" placeholder="整数"/>
        <span class="range">{{ rangeText('countMin') }}</span>
      </el-form-item>
      <el-form-item :label="labelOf('countMax')" :error="errors.countMax">
        <el-input v-model="form.countMax" style="width:160px" placeholder="整数"/>
        <span class="range">{{ rangeText('countMax') }}，需 ≥ 下限</span>
      </el-form-item>
      <el-form-item label="关键词词表" :error="errors.keywords">
        <el-input v-model="form.keywordsText" type="textarea" :rows="3"
                  :placeholder="`每行一个或用逗号分隔，最多${store.keywordLimits.maxItems}个`"/>
      </el-form-item>
      <el-form-item :label="labelOf('windowSize')" :error="errors.windowSize">
        <el-input v-model="form.windowSize" style="width:160px" placeholder="整数"/>
        <span class="range">{{ rangeText('windowSize') }} 条/窗口</span>
      </el-form-item>
      <el-form-item :label="labelOf('consecutive')" :error="errors.consecutive">
        <el-input v-model="form.consecutive" style="width:160px" placeholder="整数"/>
        <span class="range">{{ rangeText('consecutive') }} 个窗口</span>
      </el-form-item>
      <el-form-item label="生效范围" :error="errors.applyMode">
        <el-radio-group :model-value="store.applyMode" @change="onModeChange">
          <el-radio value="future">仅对后续生成的日志生效</el-radio>
          <el-radio value="all">同时重算已有结果</el-radio>
        </el-radio-group>
      </el-form-item>
    </el-form>

    <el-alert v-if="errors._global" :title="errors._global" type="error" :closable="false" class="global-err"/>

    <template #footer>
      <span class="footer-hint">{{ store.applyMode === 'all' ? '保存后将按新口径重算当前结果' : '保存后仅影响后续生成的日志' }}</span>
      <el-button size="small" @click="visible = false">取消</el-button>
      <el-button size="small" type="primary" :loading="saving" @click="save">保存</el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { reactive, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { useLogStore } from '../store/log'
import type { ApplyMode, RuleConfig } from '@/types'

const visible = defineModel<boolean>({ required: true })
const store = useLogStore()

const editType = ref('nginx')
const saving = ref(false)
const form = reactive({
  errorThreshold: '', countMin: '', countMax: '',
  keywordsText: '', windowSize: '', consecutive: ''
})
const errors = ref<Record<string, string>>({})

const labelOf = (f: string) => store.limits[f]?.label || f
const rangeText = (f: string) => {
  const s = store.limits[f]
  return s ? `${s.min} - ${s.max}` : ''
}

function parseKeywords(text: string): string[] {
  return text.split(/[\n,，;；]+/).map(s => s.trim()).filter(Boolean)
}

function loadForm() {
  const cfg = store.configs[editType.value]
  if (!cfg) return
  form.errorThreshold = String(cfg.errorThreshold)
  form.countMin = String(cfg.countMin)
  form.countMax = String(cfg.countMax)
  form.keywordsText = cfg.keywords.join('\n')
  form.windowSize = String(cfg.windowSize)
  form.consecutive = String(cfg.consecutive)
  errors.value = {}
}

watch(visible, v => { if (v) { editType.value = store.resultType; loadForm() } })
watch(editType, loadForm)

// 与后端同一份校验口径：为空 / 越界 / 上限填反均不允许保存并逐项指出
function validate(): RuleConfig | null {
  const e: Record<string, string> = {}
  const nums: Record<string, number> = {}
  const intField = (field: string, raw: string) => {
    const spec = store.limits[field]
    if (!spec) return
    const v = raw.trim()
    if (!v) { e[field] = `${spec.label}不能为空`; return }
    if (!/^-?\d+$/.test(v)) { e[field] = `${spec.label}必须为整数`; return }
    const n = parseInt(v, 10)
    if (n < spec.min || n > spec.max) { e[field] = `${spec.label}越界（允许范围 ${spec.min}-${spec.max}）`; return }
    nums[field] = n
  }
  intField('errorThreshold', form.errorThreshold)
  intField('countMin', form.countMin)
  intField('countMax', form.countMax)
  intField('windowSize', form.windowSize)
  intField('consecutive', form.consecutive)
  if (nums.countMin !== undefined && nums.countMax !== undefined && nums.countMax < nums.countMin)
    e.countMax = '窗口日志量上限小于下限（上限填反）'
  const kws = parseKeywords(form.keywordsText)
  if (!kws.length) e.keywords = '关键词词表不能为空'
  else if (kws.length > store.keywordLimits.maxItems) e.keywords = `关键词数量越界（最多${store.keywordLimits.maxItems}个）`
  else if (kws.some(k => k.length > store.keywordLimits.maxLen)) e.keywords = `存在超长关键词（单个不超过${store.keywordLimits.maxLen}字符）`
  errors.value = e
  if (Object.keys(e).length) return null
  return {
    errorThreshold: nums.errorThreshold, countMin: nums.countMin, countMax: nums.countMax,
    keywords: kws, windowSize: nums.windowSize, consecutive: nums.consecutive
  }
}

async function save() {
  const cfg = validate()
  if (!cfg) return
  saving.value = true
  try {
    const { recomputed } = await store.saveConfig(editType.value, cfg)
    ElMessage.success(recomputed ? '已保存，并按新口径重算已有结果' : '已保存，将对后续生成的日志生效')
    visible.value = false
  } catch (errs: any) {
    errors.value = { ...errs }   // 后端 422 返回的字段级不合格项
  } finally {
    saving.value = false
  }
}

async function onModeChange(mode: string | number | boolean | undefined) {
  try {
    await store.setApplyMode(mode as ApplyMode)
    ElMessage.success('生效范围已保存，重启服务后仍将沿用')
  } catch {
    ElMessage.error('生效范围保存失败')
  }
}
</script>

<style scoped>
.type-bar{display:flex;align-items:center;gap:10px;margin-bottom:14px}
.type-bar .lb{font-size:12px;color:#94a3b8}
.hint{font-size:11px;color:#64748b}
.rule-form :deep(.el-form-item__label){color:#cbd5e1;font-size:12px}
.range{margin-left:10px;font-size:11px;color:#64748b}
.global-err{margin-bottom:8px}
.footer-hint{float:left;font-size:11px;color:#64748b;line-height:24px}
</style>
