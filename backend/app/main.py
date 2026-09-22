import re, time, random, sqlite3, os
import numpy as np
from collections import Counter
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

DB_PATH = os.path.join(os.path.dirname(__file__), "rules.db")

# 每种日志类型一份判定口径：窗口大小、高频错误条数上限、窗口日志量上限、
# 连续超限次数、关键词词表。
LOG_TYPES = ["nginx", "apache", "json_app", "custom"]
DEFAULT_KEYWORDS = ["timeout", "failed", "error", "exception", "unavailable", "oom"]
DEFAULT_RULE = {
    "windowSize": 20,
    "errorLimit": 5,
    "volumeLimit": 20,
    "consecutiveLimit": 1,
    "keywords": DEFAULT_KEYWORDS,
}
# 取值边界
MIN_WINDOW, MAX_WINDOW = 1, 5000
MIN_CONSEC, MAX_CONSEC = 1, 100
MAX_KEYWORD_LEN = 50
VALID_APPLY_MODES = ["new_only", "recompute"]

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


# ---------- 持久化：规则与生效模式重启后沿用 ----------

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS anomaly_rules (
            log_type TEXT PRIMARY KEY,
            window_size INTEGER NOT NULL,
            error_limit INTEGER NOT NULL,
            volume_limit INTEGER NOT NULL,
            consecutive_limit INTEGER NOT NULL,
            keywords TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)
    for t in LOG_TYPES:
        row = conn.execute("SELECT 1 FROM anomaly_rules WHERE log_type=?", (t,)).fetchone()
        if not row:
            conn.execute(
                "INSERT INTO anomaly_rules VALUES (?,?,?,?,?,?)",
                (t, DEFAULT_RULE["windowSize"], DEFAULT_RULE["errorLimit"],
                 DEFAULT_RULE["volumeLimit"], DEFAULT_RULE["consecutiveLimit"],
                 "\n".join(DEFAULT_RULE["keywords"]))
            )
    if not conn.execute("SELECT 1 FROM settings WHERE key='applyMode'").fetchone():
        conn.execute("INSERT INTO settings VALUES (?,?)", ("applyMode", "new_only"))
    conn.commit()
    conn.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="Log Anomaly Detector", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# 最近一次为每种日志类型生成的全量日志，供“同时重算已有结果”模式复用
last_logs: dict[str, list] = {}


def db():
    return sqlite3.connect(DB_PATH)


def get_all_rules() -> dict:
    conn = db()
    out = {}
    for t, ws, el, vl, cl, kws in conn.execute(
            "SELECT log_type, window_size, error_limit, volume_limit, consecutive_limit, keywords FROM anomaly_rules"):
        out[t] = {
            "windowSize": ws, "errorLimit": el, "volumeLimit": vl,
            "consecutiveLimit": cl, "keywords": [k for k in kws.split("\n") if k]
        }
    conn.close()
    return out


def get_rule(log_type: str) -> dict:
    return get_all_rules().get(log_type, dict(DEFAULT_RULE, keywords=list(DEFAULT_KEYWORDS)))


def get_apply_mode() -> str:
    conn = db()
    row = conn.execute("SELECT value FROM settings WHERE key='applyMode'").fetchone()
    conn.close()
    return row[0] if row else "new_only"


# ---------- 校验：上限填反 / 越界 / 为空均拒绝保存 ----------

def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def validate_rule(rule) -> dict[str, str]:
    """返回 字段 -> 不合格原因，空 dict 表示通过。"""
    errors: dict[str, str] = {}
    if not isinstance(rule, dict):
        return {"_": "规则必须是对象"}

    window = rule.get("windowSize")
    if not _is_int(window) or window < MIN_WINDOW or window > MAX_WINDOW:
        errors["windowSize"] = f"判定窗口需为 {MIN_WINDOW}-{MAX_WINDOW} 之间的整数，不能为空"

    consec = rule.get("consecutiveLimit")
    if not _is_int(consec) or consec < MIN_CONSEC or consec > MAX_CONSEC:
        errors["consecutiveLimit"] = f"连续超限次数需为 {MIN_CONSEC}-{MAX_CONSEC} 之间的整数，不能为空"

    error_limit = rule.get("errorLimit")
    if not _is_int(error_limit) or error_limit < 0:
        errors["errorLimit"] = "高频错误条数上限需为不小于 0 的整数，不能为空"

    volume_limit = rule.get("volumeLimit")
    if not _is_int(volume_limit) or volume_limit < 1:
        errors["volumeLimit"] = "窗口日志量上限需为不小于 1 的整数，不能为空"

    # 上限填反：错误条数上限不能高于窗口日志量上限，日志量上限不能高于窗口大小
    if "errorLimit" not in errors and "volumeLimit" not in errors and error_limit > volume_limit:
        errors["errorLimit"] = f"高频错误条数上限({error_limit})不能高于窗口日志量上限({volume_limit})"
    if "volumeLimit" not in errors and "windowSize" not in errors and volume_limit > window:
        errors["volumeLimit"] = f"窗口日志量上限({volume_limit})不能高于判定窗口大小({window})"

    raw_keywords = rule.get("keywords")
    if not isinstance(raw_keywords, list) or len(raw_keywords) == 0:
        errors["keywords"] = "关键词词表不能为空，每行一个关键词"
    else:
        cleaned = []
        for k in raw_keywords:
            if not isinstance(k, str):
                errors["keywords"] = "关键词必须是文本，每行一个"
                break
            kw = k.strip()
            if not kw:
                errors["keywords"] = "关键词词表不能包含空行，请删除空白项"
                break
            if len(kw) > MAX_KEYWORD_LEN:
                errors["keywords"] = f"单个关键词不能超过 {MAX_KEYWORD_LEN} 个字符：{kw}"
                break
            if kw.lower() not in [x.lower() for x in cleaned]:
                cleaned.append(kw)
        else:
            rule["keywords"] = cleaned
    return errors


# ---------- 请求模型 ----------

class GenerateRequest(BaseModel):
    type: str = "nginx"
    count: int = 1000


class DetectRequest(BaseModel):
    type: str = "nginx"
    logs: list | None = None
    query: str = ""


class RuleUpdateRequest(BaseModel):
    rule: dict
    applyMode: str | None = None


class ApplyModeRequest(BaseModel):
    applyMode: str


# ---------- API ----------

@app.get("/api/rules")
def list_rules():
    return {"rules": get_all_rules(), "applyMode": get_apply_mode(), "logTypes": LOG_TYPES}


@app.put("/api/rules/{log_type}")
def update_rule(log_type: str, req: RuleUpdateRequest):
    if log_type not in LOG_TYPES:
        raise HTTPException(status_code=404, detail=f"未知日志类型: {log_type}")

    errors = validate_rule(req.rule)
    if req.applyMode is not None and req.applyMode not in VALID_APPLY_MODES:
        errors["applyMode"] = "生效方式只能是 new_only 或 recompute"
    if errors:
        raise HTTPException(status_code=422, detail={"message": "存在不合格项，未保存", "errors": errors})

    r = req.rule
    conn = db()
    conn.execute(
        "UPDATE anomaly_rules SET window_size=?, error_limit=?, volume_limit=?, "
        "consecutive_limit=?, keywords=? WHERE log_type=?",
        (r["windowSize"], r["errorLimit"], r["volumeLimit"], r["consecutiveLimit"],
         "\n".join(r["keywords"]), log_type)
    )
    if req.applyMode is not None:
        conn.execute("INSERT INTO settings(key,value) VALUES('applyMode',?) "
                     "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (req.applyMode,))
    conn.commit()
    conn.close()

    apply_mode = req.applyMode if req.applyMode is not None else get_apply_mode()
    result = None
    recomputed = False
    # 选择“同时重算已有结果”时，立即按新口径重算该类型已有日志
    if apply_mode == "recompute" and last_logs.get(log_type):
        result = analyze_logs(last_logs[log_type], get_rule(log_type), "")
        recomputed = True

    return {
        "rules": get_all_rules(),
        "applyMode": apply_mode,
        "recomputed": recomputed,
        "result": result
    }


@app.put("/api/settings/apply-mode")
def update_apply_mode(req: ApplyModeRequest):
    if req.applyMode not in VALID_APPLY_MODES:
        raise HTTPException(status_code=422, detail={"message": "生效方式非法",
                                                     "errors": {"applyMode": "只能选择 new_only 或 recompute"}})
    conn = db()
    conn.execute("INSERT INTO settings(key,value) VALUES('applyMode',?) "
                 "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (req.applyMode,))
    conn.commit()
    conn.close()
    return {"applyMode": req.applyMode}


@app.post("/api/generate")
def generate_logs(req: GenerateRequest):
    log_type = req.type if req.type in LOG_TEMPLATES else "nginx"
    tmpl = LOG_TEMPLATES[log_type]
    count = max(1, min(int(req.count or 1000), 10000))
    logs = []
    for i in range(count):
        entry = tmpl["generator"]()
        logs.append({
            "id": i + 1,
            "timestamp": entry["timestamp"],
            "level": entry["level"],
            "source": entry["source"],
            "message": entry["message"],
            "raw": f"[{entry['timestamp']}] [{entry['level']}] [{entry['source']}] {entry['message']}"
        })
    last_logs[log_type] = logs
    # 生成时始终使用该日志类型已保存的口径（重启后沿用），所有面板同一口径
    return analyze_logs(logs, get_rule(log_type), "")


@app.post("/api/detect")
def detect_anomalies(req: DetectRequest):
    log_type = req.type if req.type in LOG_TYPES else "nginx"
    logs = req.logs if req.logs is not None else last_logs.get(log_type)
    if not logs:
        raise HTTPException(status_code=400, detail="没有可检测的日志，请先生成日志")
    if req.logs is not None:
        last_logs[log_type] = list(logs)
    return analyze_logs(logs, get_rule(log_type), req.query)


def analyze_logs(logs_data, rule, query):
    """所有面板共用的同一份口径：窗口、统计异常、规则告警均按 rule 计算。"""
    logs = logs_data
    n = len(logs)

    window_size = int(rule["windowSize"])
    windows = []
    for i in range(0, n, window_size):
        chunk = logs[i:i + window_size]
        levels = Counter(l["level"] for l in chunk)
        sources = Counter(l["source"] for l in chunk)
        error_count = sum(c for lv, c in levels.items() if str(lv).lower() == "error")
        keyword_hits = 0
        for l in chunk:
            raw_lower = str(l.get("raw", "")).lower()
            if any(str(k).lower() in raw_lower for k in rule["keywords"]):
                keyword_hits += 1
        windows.append({
            "start": i, "end": min(i + window_size, n),
            "count": len(chunk),
            "levels": dict(levels),
            "sources": dict(sources),
            "errorCount": error_count,
            "keywordHits": keyword_hits
        })

    # 3-sigma + IQR 统计异常（窗口大小同样取自规则，保证口径一致）
    counts = [w["count"] for w in windows]
    mean = float(np.mean(counts))
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
            iqr_score = min(10.0, abs(w["count"] - mean) / max(iqr, 1e-5))
        anomalies.append({
            "windowIndex": i,
            "sigmaScore": round(sigma_score, 2),
            "iqrScore": round(iqr_score, 2),
            "isAnomaly": sigma_score > 2.5 or iqr_score > 3.0,
            "timestamp": logs[i * window_size]["timestamp"] if i * window_size < len(logs) else ""
        })

    alerts = []

    def emit(rule_name, severity, message, ts):
        alerts.append({
            "id": len(alerts) + 1, "ruleName": rule_name, "severity": severity,
            "message": message, "timestamp": ts
        })

    def run_streak(name, severity, limit, value, make_message):
        # 连续超限 consecutiveLimit 个窗口才告一次；中断后重新计数
        streak = 0
        for w in windows:
            if value(w) > limit:
                streak += 1
                if streak == int(rule["consecutiveLimit"]):
                    emit(name, severity, make_message(w),
                         logs[w["start"]]["timestamp"] if w["start"] < len(logs) else time.strftime("%H:%M:%S"))
            else:
                streak = 0

    run_streak(
        "高频ERROR", "high",
        int(rule["errorLimit"]), lambda w: w["errorCount"],
        lambda w: f"窗口{w['start']}起连续{rule['consecutiveLimit']}个窗口ERROR日志超过{rule['errorLimit']}条"
                  f"（当前窗口{w['errorCount']}条）"
    )
    run_streak(
        "异常流量", "medium",
        int(rule["volumeLimit"]), lambda w: w["count"],
        lambda w: f"窗口{w['start']}起连续{rule['consecutiveLimit']}个窗口日志量超过{rule['volumeLimit']}"
                  f"（当前窗口{w['count']}条）"
    )
    run_streak(
        "关键词命中", "low",
        0, lambda w: w["keywordHits"],
        lambda w: f"窗口{w['start']}起连续{rule['consecutiveLimit']}个窗口命中关键词"
                  f"（当前窗口{w['keywordHits']}条，词表{len(rule['keywords'])}个）"
    )

    # 全文检索（排序，不参与判定）
    if query:
        query_terms = query.lower().split()
        scored = []
        for log in logs:
            raw_lower = log["raw"].lower()
            score = sum(1 for t in query_terms if t in raw_lower)
            if score > 0:
                scored.append((score, log))
        logs = [l for _, l in sorted(scored, key=lambda x: x[0], reverse=True)]

    # 统计型异常告警
    for a in anomalies:
        if a["isAnomaly"]:
            alerts.append({
                "id": len(alerts) + 1, "ruleName": "统计异常检测",
                "severity": "critical" if a["sigmaScore"] > 4 else "high",
                "message": f"窗口{a['windowIndex']}: 3-sigma={a['sigmaScore']}, IQR={a['iqrScore']}",
                "timestamp": a["timestamp"]
            })

    return {
        "logs": logs[:200],
        "windows": windows,
        "anomalies": anomalies,
        "alerts": alerts[:20],
        "totalLogs": n,
        "appliedRule": {
            "windowSize": rule["windowSize"],
            "errorLimit": rule["errorLimit"],
            "volumeLimit": rule["volumeLimit"],
            "consecutiveLimit": rule["consecutiveLimit"],
            "keywords": list(rule["keywords"])
        }
    }
