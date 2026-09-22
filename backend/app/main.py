import re, math, time, random, json
from pathlib import Path
from typing import Optional
import numpy as np
from collections import defaultdict, Counter
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Log Anomaly Detector")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

LOG_TEMPLATES = {
    "nginx": {
        "pattern": r'(?P<timestamp>\S+ \+\d{4}) (?P<source>\S+) (?P<level>\w+) (?P<message>.+)',
        "generator": lambda: {
            "timestamp": f"{random.randint(1,28):02d}/{'Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split()[random.randint(0,11)]}/{2024}:{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d} +0000",
            "source": random.choice(["nginx", "api-gateway", "load-balancer"]),
            "level": random.choices(["INFO", "WARN", "ERROR", "DEBUG"], weights=[50, 15, 5, 30])[0],
            "message": random.choice([
                'GET /api/users 200 0.032s', 'POST /api/orders 201 0.145s', 'GET /api/products 304 0.008s',
                'GET /static/main.js 200 0.002s', 'POST /api/login 401 0.023s', 'GET /admin 403 0.005s',
                'GET /api/health 200 0.001s', 'GET /api/orders?page=2 200 0.056s', 'connection timeout upstream',
                'SSL handshake failed', 'worker process exited on signal 9', 'upstream server unavailable'
            ])
        }
    },
    "apache": {
        "pattern": r'\[(?P<timestamp>[^\]]+)\] \[(?P<level>\w+)\] \[(?P<source>\S+)\] (?P<message>.+)',
        "generator": lambda: {
            "timestamp": f"{'Sun Mon Tue Wed Thu Fri Sat'.split()[random.randint(0,6)]} {'Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split()[random.randint(0,11)]} {random.randint(1,28):02d} {random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d} {2024}",
            "source": random.choice(["httpd", "mod_ssl", "mod_rewrite"]),
            "level": random.choices(["notice", "warn", "error", "info"], weights=[40, 15, 5, 40])[0],
            "message": random.choice(["server configured", "caught SIGTERM", "resuming normal ops", "request exceeded limit",
                        "file does not exist", "client denied by server", "Invalid method in request"])
        }
    },
    "json_app": {
        "pattern": None,
        "generator": lambda: {
            "timestamp": f"{2024}-{random.randint(1,12):02d}-{random.randint(1,28):02d}T{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}.{random.randint(0,999):03d}Z",
            "source": random.choice(["user-service", "order-service", "payment-service", "auth-service"]),
            "level": random.choices(["INFO", "WARN", "ERROR", "DEBUG"], weights=[45, 20, 5, 30])[0],
            "message": random.choice([
                'User login successful user_id=10' + str(random.randint(100, 999)),
                'Order created order_id=ORD-' + str(random.randint(10000, 99999)),
                'Payment processed amount=' + str(random.randint(10, 999)),
                'Database connection pool exhausted',
                'Cache miss for key user_session_' + str(random.randint(100, 999)),
                'Circuit breaker opened for service payment',
                'Request latency exceeds threshold 5000ms',
                'NullPointerException at com.app.controller.UserController.getProfile'
            ])
        }
    },
    "custom": {
        "pattern": None,
        "generator": lambda: {
            "timestamp": str(int(time.time() - random.randint(0, 86400))),
            "source": random.choice(["cron", "systemd", "kernel", "docker"]),
            "level": random.choices(["info", "warning", "error", "debug"], weights=[40, 20, 5, 35])[0],
            "message": random.choice(["OOM killer invoked", "disk usage above 90%", "container restarted", "NTP sync lost",
                        "process oom_score_adj=500", "firewall rule updated", "mount point not found"])
        }
    }
}

# ---------- 规则配置：按日志类型分别可调，持久化到磁盘，重启后沿用 ----------

CONFIG_PATH = Path(__file__).resolve().parent / "rule_config.json"

# 各字段取值范围（前后端同一份校验口径，通过 GET /api/config 下发）
FIELD_LIMITS = {
    "errorThreshold": {"min": 1, "max": 1000, "label": "高频ERROR条数上限"},
    "countMin":       {"min": 0, "max": 100000, "label": "窗口日志量下限"},
    "countMax":       {"min": 1, "max": 100000, "label": "窗口日志量上限"},
    "windowSize":     {"min": 5, "max": 500, "label": "判定窗口大小"},
    "consecutive":    {"min": 1, "max": 20, "label": "连续超限次数"},
}
KEYWORD_LIMITS = {"maxItems": 50, "maxLen": 50}

DEFAULT_CONFIGS = {
    "nginx":    {"errorThreshold": 5, "countMin": 0, "countMax": 30, "keywords": ["timeout", "failed", "unavailable"], "windowSize": 20, "consecutive": 2},
    "apache":   {"errorThreshold": 5, "countMin": 0, "countMax": 30, "keywords": ["denied", "SIGTERM", "exceeded"], "windowSize": 20, "consecutive": 2},
    "json_app": {"errorThreshold": 5, "countMin": 0, "countMax": 30, "keywords": ["exhausted", "Circuit breaker", "NullPointerException"], "windowSize": 20, "consecutive": 2},
    "custom":   {"errorThreshold": 5, "countMin": 0, "countMax": 30, "keywords": ["OOM", "disk usage", "restarted"], "windowSize": 20, "consecutive": 2},
}

APPLY_MODES = ("future", "all")  # future=仅对后续生成的日志生效, all=同时重算已有结果


def load_state():
    configs = {t: dict(DEFAULT_CONFIGS[t]) for t in LOG_TEMPLATES}
    apply_mode = "all"
    if CONFIG_PATH.exists():
        try:
            data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            for t in LOG_TEMPLATES:
                saved = data.get("configs", {}).get(t)
                if isinstance(saved, dict):
                    errors, cleaned = validate_config({**configs[t], **saved})
                    if not errors:
                        configs[t] = cleaned
            if data.get("applyMode") in APPLY_MODES:
                apply_mode = data["applyMode"]
        except (json.JSONDecodeError, OSError):
            pass
    return configs, apply_mode


def save_state():
    CONFIG_PATH.write_text(
        json.dumps({"configs": CONFIGS, "applyMode": APPLY_MODE}, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )


def validate_config(cfg):
    """返回 (errors, cleaned)。上限填反 / 越界 / 为空均按字段指出。"""
    errors, cleaned = {}, {}
    if not isinstance(cfg, dict):
        return {"_global": "配置格式不正确"}, cleaned
    for key, spec in FIELD_LIMITS.items():
        v = cfg.get(key)
        if v is None or (isinstance(v, str) and not v.strip()):
            errors[key] = f"{spec['label']}不能为空"
            continue
        if isinstance(v, str):
            v = v.strip()
            if re.fullmatch(r"-?\d+", v):
                v = int(v)
        if isinstance(v, bool) or not isinstance(v, (int, float)) or int(v) != v:
            errors[key] = f"{spec['label']}必须为整数"
            continue
        v = int(v)
        if v < spec["min"] or v > spec["max"]:
            errors[key] = f"{spec['label']}越界（允许范围 {spec['min']}-{spec['max']}）"
            continue
        cleaned[key] = v
    if "countMin" in cleaned and "countMax" in cleaned and cleaned["countMax"] < cleaned["countMin"]:
        errors["countMax"] = "窗口日志量上限小于下限（上限填反）"
    kws = cfg.get("keywords")
    kws_clean = [k.strip() for k in kws if isinstance(k, str) and k.strip()] if isinstance(kws, list) else []
    if not kws_clean:
        errors["keywords"] = "关键词词表不能为空"
    elif len(kws_clean) > KEYWORD_LIMITS["maxItems"]:
        errors["keywords"] = f"关键词数量越界（最多{KEYWORD_LIMITS['maxItems']}个）"
    elif any(len(k) > KEYWORD_LIMITS["maxLen"] for k in kws_clean):
        errors["keywords"] = f"存在超长关键词（单个不超过{KEYWORD_LIMITS['maxLen']}字符）"
    else:
        cleaned["keywords"] = kws_clean
    return errors, cleaned


CONFIGS, APPLY_MODE = load_state()

# 最近一次生成/检测的完整日志（内存态），用于按同一份口径重算已有结果
LAST = {"logs": [], "type": "nginx"}


class GenerateRequest(BaseModel):
    type: str = "nginx"
    count: int = 1000


class DetectRequest(BaseModel):
    logType: Optional[str] = None
    query: str = ""


class ConfigUpdate(BaseModel):
    logType: str
    config: dict


class ApplyModeUpdate(BaseModel):
    applyMode: str


@app.get("/api/config")
def get_config():
    return {
        "configs": CONFIGS,
        "applyMode": APPLY_MODE,
        "limits": FIELD_LIMITS,
        "keywordLimits": KEYWORD_LIMITS,
        "logTypes": list(LOG_TEMPLATES.keys()),
    }


@app.put("/api/config")
def update_config(req: ConfigUpdate):
    if req.logType not in LOG_TEMPLATES:
        raise HTTPException(status_code=400, detail=f"未知日志类型: {req.logType}")
    errors, cleaned = validate_config(req.config)
    if errors:
        raise HTTPException(status_code=422, detail={"message": "配置校验失败，请修正不合格项", "errors": errors})
    CONFIGS[req.logType] = cleaned
    save_state()
    return {"ok": True, "configs": CONFIGS, "applyMode": APPLY_MODE}


@app.put("/api/apply-mode")
def update_apply_mode(req: ApplyModeUpdate):
    global APPLY_MODE
    if req.applyMode not in APPLY_MODES:
        raise HTTPException(status_code=422, detail={"message": "生效范围取值非法", "errors": {"applyMode": "仅支持 future 或 all"}})
    APPLY_MODE = req.applyMode
    save_state()
    return {"ok": True, "applyMode": APPLY_MODE}


@app.post("/api/generate")
def generate_logs(req: GenerateRequest):
    log_type = req.type if req.type in LOG_TEMPLATES else "nginx"
    tmpl = LOG_TEMPLATES[log_type]
    logs = []
    for i in range(req.count):
        entry = tmpl["generator"]()
        logs.append({
            "id": i + 1,
            "timestamp": entry["timestamp"],
            "level": entry["level"],
            "source": entry["source"],
            "message": entry["message"],
            "raw": f"[{entry['timestamp']}] [{entry['level']}] [{entry['source']}] {entry['message']}"
        })
    LAST["logs"] = logs
    LAST["type"] = log_type
    return analyze_logs(logs, "", CONFIGS[log_type], log_type)


@app.post("/api/detect")
def detect_anomalies(req: DetectRequest):
    if not LAST["logs"]:
        raise HTTPException(status_code=400, detail="没有可检测的日志，请先生成日志")
    log_type = req.logType if req.logType in LOG_TEMPLATES else LAST["type"]
    return analyze_logs(LAST["logs"], req.query, CONFIGS[log_type], log_type)


def _streak_alerts(windows, flags, consecutive, alerts, make_alert):
    """连续超限 consecutive 个窗口才告警，每段连超只报一次。"""
    streak = 0
    for i, (w, flag) in enumerate(zip(windows, flags)):
        if flag:
            streak += 1
            if streak == consecutive:
                alerts.append(make_alert(w, i))
        else:
            streak = 0


def analyze_logs(logs_data, query, cfg, log_type):
    logs = logs_data
    n = len(logs)

    # 判定窗口大小取自该日志类型的规则配置
    window_size = max(1, int(cfg.get("windowSize", 20)))
    consecutive = max(1, int(cfg.get("consecutive", 1)))
    keywords = [k.lower() for k in cfg.get("keywords", [])]

    windows = []
    kw_matched_per_window = []
    for i in range(0, n, window_size):
        chunk = logs[i:i + window_size]
        levels = Counter(l["level"] for l in chunk)
        sources = Counter(l["source"] for l in chunk)
        error_count = sum(c for lv, c in levels.items() if str(lv).upper() == "ERROR")
        matched = sorted({k for l in chunk for k in keywords if k in l["raw"].lower()})
        kw_matched_per_window.append(matched)
        windows.append({
            "start": i, "end": min(i + window_size, n),
            "count": len(chunk),
            "levels": dict(levels),
            "sources": dict(sources),
            "errorCount": error_count,
            "keywordHits": len(matched)
        })

    # 3-sigma + IQR anomaly detection
    counts = [w["count"] for w in windows]
    mean = float(np.mean(counts)) if counts else 0.0
    std = float(np.std(counts)) if len(counts) > 1 else 1.0
    q1 = float(np.percentile(counts, 25)) if len(counts) > 3 else mean - std
    q3 = float(np.percentile(counts, 75)) if len(counts) > 3 else mean + std
    iqr = q3 - q1 if q3 > q1 else 1.0

    anomalies = []
    for i, w in enumerate(windows):
        sigma_score = abs(w["count"] - mean) / max(std, 1e-5)
        iqr_low = q1 - 1.5 * iqr
        iqr_high = q3 + 1.5 * iqr
        iqr_score = 0.0
        if w["count"] < iqr_low or w["count"] > iqr_high:
            iqr_score = min(10.0, abs(w["count"] - (mean)) / max(iqr, 1e-5))
        anomalies.append({
            "windowIndex": i,
            "sigmaScore": round(sigma_score, 2),
            "iqrScore": round(iqr_score, 2),
            "isAnomaly": sigma_score > 2.5 or iqr_score > 3.0,
            "timestamp": logs[i * window_size]["timestamp"] if i * window_size < len(logs) else ""
        })

    # 规则告警：高频ERROR / 窗口日志量 / 关键词命中，均需连续超限指定次数
    alerts = []
    now = time.strftime("%H:%M:%S")
    err_thr, cnt_min, cnt_max = cfg["errorThreshold"], cfg["countMin"], cfg["countMax"]

    _streak_alerts(
        windows, [w["errorCount"] > err_thr for w in windows], consecutive, alerts,
        lambda w, i: {"ruleName": "高频ERROR", "severity": "high",
                      "message": f"窗口{w['start']}~{w['end']}: ERROR日志{w['errorCount']}条超过上限{err_thr}（连续{consecutive}个窗口超限）",
                      "timestamp": now})
    _streak_alerts(
        windows, [w["count"] > cnt_max or w["count"] < cnt_min for w in windows], consecutive, alerts,
        lambda w, i: {"ruleName": "异常流量", "severity": "medium",
                      "message": f"窗口{w['start']}~{w['end']}: 日志量{w['count']}超出范围[{cnt_min}, {cnt_max}]（连续{consecutive}个窗口超限）",
                      "timestamp": now})
    _streak_alerts(
        windows, [bool(m) for m in kw_matched_per_window], consecutive, alerts,
        lambda w, i: {"ruleName": "关键词命中", "severity": "medium",
                      "message": f"窗口{w['start']}~{w['end']}: 命中关键词 {', '.join(kw_matched_per_window[i])}（连续{consecutive}个窗口超限）",
                      "timestamp": now})

    # Full-text search with TF-IDF
    if query:
        query_terms = query.lower().split()
        scored = []
        for log in logs:
            raw_lower = log["raw"].lower()
            score = sum(1 for t in query_terms if t in raw_lower)
            if score > 0:
                scored.append((score, log))
        logs = [l for _, l in sorted(scored, key=lambda x: x[0], reverse=True)]

    # Add non-rule alerts for high anomaly windows
    for a in anomalies:
        if a["isAnomaly"]:
            alerts.append({
                "ruleName": "统计异常检测",
                "severity": "critical" if a["sigmaScore"] > 4 else "high",
                "message": f"窗口{a['windowIndex']}: 3-sigma={a['sigmaScore']}, IQR={a['iqrScore']}",
                "timestamp": a["timestamp"]
            })

    for idx, alert in enumerate(alerts):
        alert["id"] = idx + 1

    return {
        "logs": logs[:200],
        "windows": windows,
        "anomalies": anomalies,
        "alerts": alerts[:20],
        "totalLogs": n,
        "logType": log_type,
        "appliedConfig": cfg
    }
