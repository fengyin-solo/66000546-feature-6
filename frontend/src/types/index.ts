export interface LogEntry { id: number; timestamp: string; level: string; source: string; message: string; raw: string }
export interface TimeWindow { start: number; end: number; count: number; levels: Record<string,number>; sources: Record<string,number>; errorCount?: number; keywordHits?: number }
export interface AnomalyScore { windowIndex: number; sigmaScore: number; iqrScore: number; isAnomaly: boolean; timestamp: string }
export interface Alert { id: number; ruleName: string; severity: string; message: string; timestamp: string }
/** 按日志类型分别配置的异常判定口径 */
export interface AnomalyRule {
  windowSize: number
  errorLimit: number
  volumeLimit: number
  consecutiveLimit: number
  keywords: string[]
}
/** new_only: 只对后续生成的日志生效; recompute: 同时重算已有结果 */
export type ApplyMode = 'new_only' | 'recompute'
export interface AppliedRule extends AnomalyRule { logType?: string }
export interface AnalysisResult { logs: LogEntry[]; windows: TimeWindow[]; anomalies: AnomalyScore[]; alerts: Alert[]; totalLogs: number; appliedRule?: AppliedRule }
