export interface LogEntry { id: number; timestamp: string; level: string; source: string; message: string; raw: string }
export interface TimeWindow { start: number; end: number; count: number; levels: Record<string,number>; sources: Record<string,number>; errorCount?: number; keywordHits?: number }
export interface AnomalyScore { windowIndex: number; sigmaScore: number; iqrScore: number; isAnomaly: boolean; timestamp: string }
export interface Alert { id: number; ruleName: string; severity: string; message: string; timestamp: string }

export interface RuleConfig {
  errorThreshold: number   // 高频ERROR条数上限
  countMin: number         // 窗口日志量下限
  countMax: number         // 窗口日志量上限
  keywords: string[]       // 关键词命中词表
  windowSize: number       // 判定窗口大小
  consecutive: number      // 连续超限次数
}
export type ApplyMode = 'future' | 'all'  // future=仅对后续生成的日志生效, all=同时重算已有结果
export interface FieldLimit { min: number; max: number; label: string }
export interface ConfigResponse {
  configs: Record<string, RuleConfig>
  applyMode: ApplyMode
  limits: Record<string, FieldLimit>
  keywordLimits: { maxItems: number; maxLen: number }
  logTypes: string[]
}
export interface AnalysisResult {
  logs: LogEntry[]; windows: TimeWindow[]; anomalies: AnomalyScore[]; alerts: Alert[]; totalLogs: number
  logType?: string; appliedConfig?: RuleConfig
}
