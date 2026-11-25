#!/usr/bin/env bash
set -euo pipefail

ROOT="$(pwd)"

if [[ ! -f "$ROOT/pyproject.toml" || ! -d "$ROOT/src/mailsleuth" ]]; then
  echo "ERROR: Run this from the MailSleuth project root."
  exit 1
fi

mkdir -p src/mailsleuth frontend/src data

# ---------------- BACKEND ----------------

cat > src/mailsleuth/api.py <<'PY'
"""Local FastAPI interface for the MailSleuth investigation engine."""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from mailsleuth.core.pipeline import investigate
from mailsleuth.reporting.reporter import write_reports
from mailsleuth.storage.database import CaseDatabase

ROOT = Path(__file__).resolve().parents[2]
DB_PATH = ROOT / "data" / "mailsleuth.db"
REPORTS = ROOT / "reports"
MAX_UPLOAD = 20 * 1024 * 1024

app = FastAPI(
    title="MailSleuth API",
    description="Local-first phishing email investigation API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "MailSleuth API"}


@app.post("/api/analyze")
async def analyze_email(file: UploadFile = File(...)):
    filename = Path(file.filename or "").name

    if not filename.lower().endswith(".eml"):
        raise HTTPException(400, "Only .eml files are supported.")

    content = await file.read(MAX_UPLOAD + 1)

    if not content:
        raise HTTPException(400, "Uploaded email is empty.")

    if len(content) > MAX_UPLOAD:
        raise HTTPException(413, "Maximum email size is 20 MB.")

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            prefix="mailsleuth_", suffix=".eml", delete=False
        ) as temporary:
            temporary.write(content)
            temp_path = Path(temporary.name)

        result = investigate(temp_path, DB_PATH)
        write_reports(result, REPORTS)

        return result

    except (ValueError, OSError) as exc:
        raise HTTPException(422, str(exc)) from exc

    except Exception as exc:
        # Avoid exposing internal paths or stack traces to the browser.
        raise HTTPException(500, "Investigation failed. Check the API log.") from exc

    finally:
        await file.close()
        if temp_path and temp_path.exists():
            temp_path.unlink()


@app.get("/api/cases")
def list_cases():
    return CaseDatabase(DB_PATH).list_cases()


@app.get("/api/cases/{case_id}")
def get_case(case_id: str):
    if not re.fullmatch(r"MS-[A-F0-9]{12}", case_id):
        raise HTTPException(400, "Invalid case ID.")

    case = CaseDatabase(DB_PATH).get_case(case_id)

    if case is None:
        raise HTTPException(404, "Case not found.")

    return case


@app.get("/api/reports/{case_id}/{report_format}")
def download_report(case_id: str, report_format: str):
    if not re.fullmatch(r"MS-[A-F0-9]{12}", case_id):
        raise HTTPException(400, "Invalid case ID.")

    extensions = {"json": "json", "markdown": "md"}
    extension = extensions.get(report_format)

    if not extension:
        raise HTTPException(400, "Format must be json or markdown.")

    path = REPORTS / f"{case_id}.{extension}"

    if not path.is_file():
        raise HTTPException(404, "Report not found.")

    return FileResponse(
        path,
        filename=path.name,
        media_type="application/octet-stream",
    )
PY

# ---------------- FRONTEND ----------------

cat > frontend/package.json <<'JSON'
{
  "name": "mailsleuth-dashboard",
  "private": true,
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc -b && vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "@vitejs/plugin-react": "^4.3.4",
    "vite": "^6.0.7",
    "react": "^19.0.0",
    "react-dom": "^19.0.0",
    "lucide-react": "^0.468.0"
  },
  "devDependencies": {
    "@types/react": "^19.0.0",
    "@types/react-dom": "^19.0.0",
    "typescript": "~5.7.2"
  }
}
JSON

cat > frontend/index.html <<'HTML'
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="theme-color" content="#090d16" />
    <meta name="description" content="MailSleuth email forensics investigation console" />
    <title>MailSleuth | Email Forensics</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
HTML

cat > frontend/vite.config.ts <<'TS'
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true
  }
});
TS

cat > frontend/tsconfig.json <<'JSON'
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true
  },
  "include": ["src"]
}
JSON

cat > frontend/src/main.tsx <<'TSX'
import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./style.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode><App /></React.StrictMode>
);
TSX

cat > frontend/src/App.tsx <<'TSX'
import { useEffect, useState } from "react";
import {
  Activity, AlertTriangle, ArrowUpRight, CheckCircle2, ChevronRight,
  Clock3, Download, FileSearch, FileText, Fingerprint, FolderOpen,
  Globe, History, LoaderCircle, Mail, RefreshCw, Shield, ShieldAlert,
  ShieldCheck, Upload, XCircle
} from "lucide-react";

const API = "http://127.0.0.1:8000";

type Finding = {
  category: string;
  indicator: string;
  severity: string;
  explanation: string;
  evidence: string;
};

type Result = {
  case_id: string;
  email: {
    subject: string;
    sender: string;
    source_file: string;
    date: string;
    message_id: string;
  };
  assessment: {
    verdict: string;
    risk_score: number;
    confidence: string;
    limitations: string[];
  };
  findings: Finding[];
  urls: Array<{
    original_url: string;
    domain: string;
    indicators: string[];
    suspicious: boolean;
  }>;
  attachments: Array<{
    filename: string;
    size: number;
    sha256: string;
    detected_signature: string;
    findings: Array<{indicator: string; severity: string}>;
  }>;
};

type CaseItem = {
  case_id: string;
  source_file: string;
  subject: string;
  sender: string;
  verdict: string;
  risk_score: number;
  created_at: string;
};

function App() {
  const [health, setHealth] = useState(false);
  const [cases, setCases] = useState<CaseItem[]>([]);
  const [result, setResult] = useState<Result | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [tab, setTab] = useState("overview");

  async function loadData() {
    try {
      const [h, c] = await Promise.all([
        fetch(`${API}/api/health`),
        fetch(`${API}/api/cases`)
      ]);
      if (!h.ok || !c.ok) throw new Error("API unavailable");
      setHealth(true);
      setCases(await c.json());
    } catch {
      setHealth(false);
    }
  }

  useEffect(() => {
    loadData();
    const timer = window.setInterval(loadData, 10000);
    return () => window.clearInterval(timer);
  }, []);

  async function analyze() {
    if (!file) {
      setError("Select an .eml file first.");
      return;
    }
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const form = new FormData();
      form.append("file", file);
      const response = await fetch(`${API}/api/analyze`, {
        method: "POST",
        body: form
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Analysis failed.");
      setResult(data);
      setTab("overview");
      setFile(null);
      const input = document.getElementById("email-file") as HTMLInputElement;
      if (input) input.value = "";
      await loadData();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unexpected error.");
    } finally {
      setLoading(false);
    }
  }

  async function openCase(id: string) {
    setError("");
    try {
      const response = await fetch(`${API}/api/cases/${id}`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Could not load case.");
      setResult({
        case_id: data.case_id,
        email: {
          subject: data.subject,
          sender: data.sender,
          source_file: data.source_file,
          date: data.created_at,
          message_id: ""
        },
        assessment: {
          verdict: data.verdict,
          risk_score: data.risk_score,
          confidence: "limited",
          limitations: ["Saved case view contains stored case records. Run a new analysis to view the full analyzer output."]
        },
        findings: (data.findings || []).map((f: any) => ({
          category: f.category,
          indicator: f.indicator,
          severity: f.severity,
          explanation: f.explanation,
          evidence: f.evidence
        })),
        urls: [],
        attachments: []
      });
      setTab("overview");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load case.");
    }
  }

  const score = result?.assessment.risk_score ?? 0;
  const verdict = result?.assessment.verdict ?? "";
  const riskClass = verdict === "HIGH_RISK" ? "danger"
    : verdict === "SUSPICIOUS" ? "warning" : "safe";

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon"><Shield size={22}/></div>
          <div><strong>MailSleuth</strong><small>EMAIL FORENSICS</small></div>
        </div>
        <div className="side-label">WORKSPACE</div>
        <button className="nav-item active"><Activity size={17}/> Investigation Console</button>
        <button className="nav-item" onClick={() => {setResult(null); setTab("overview");}}>
          <FolderOpen size={17}/> New Investigation
        </button>
        <div className="side-label history-label">RECENT CASES</div>
        <div className="case-nav">
          {cases.slice(0, 8).map(c => (
            <button key={c.case_id} className="case-nav-item" onClick={() => openCase(c.case_id)}>
              <span className={`tiny-dot ${c.verdict === "HIGH_RISK" ? "red" : c.verdict === "SUSPICIOUS" ? "yellow" : "green"}`}/>
              <span className="case-nav-text">{c.subject || c.source_file}<small>{c.case_id}</small></span>
            </button>
          ))}
          {cases.length === 0 && <p className="empty-small">No investigations yet.</p>}
        </div>
        <div className="sidebar-bottom">
          <div className="local-card">
            <span className={`status-dot ${health ? "online" : "offline"}`}/>
            <div><strong>{health ? "Local engine online" : "Backend unavailable"}</strong><small>{health ? "Analysis runs locally" : "Start the API service"}</small></div>
          </div>
          <small className="version">MAILSLEUTH v1.0.0 · LOCAL MODE</small>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div className="breadcrumbs">Workspace <ChevronRight size={14}/> <strong>Investigation Console</strong></div>
          <div className="top-right">
            <span className={`connection ${health ? "connected" : "disconnected"}`}>
              <span className="status-dot"/> {health ? "API CONNECTED" : "API OFFLINE"}
            </span>
            <button className="icon-button" onClick={loadData} title="Refresh"><RefreshCw size={16}/></button>
          </div>
        </header>

        <div className="content">
          <section className="page-heading">
            <div>
              <div className="eyebrow">SECURITY OPERATIONS / EMAIL ANALYSIS</div>
              <h1>Investigation Console</h1>
              <p>Analyze suspicious emails, inspect evidence, and document threat assessments.</p>
            </div>
            <div className="heading-chip"><ShieldCheck size={15}/> Evidence-based analysis</div>
          </section>

          <section className="stats-grid">
            <div className="stat-card"><div className="stat-icon blue"><FolderOpen/></div><div><span>Total cases</span><strong>{cases.length}</strong></div><small>Stored investigations</small></div>
            <div className="stat-card"><div className="stat-icon red"><ShieldAlert/></div><div><span>High risk</span><strong>{cases.filter(c => c.verdict === "HIGH_RISK").length}</strong></div><small>Require analyst review</small></div>
            <div className="stat-card"><div className="stat-icon yellow"><AlertTriangle/></div><div><span>Suspicious</span><strong>{cases.filter(c => c.verdict === "SUSPICIOUS").length}</strong></div><small>Indicators detected</small></div>
            <div className="stat-card"><div className="stat-icon green"><ShieldCheck/></div><div><span>No strong indicators</span><strong>{cases.filter(c => c.verdict === "NO_STRONG_INDICATORS").length}</strong></div><small>Not a safety guarantee</small></div>
          </section>

          <section className="upload-panel">
            <div className="section-title">
              <div><div className="eyebrow">NEW CASE</div><h2>Email investigation</h2></div>
              <span className="file-limit">EML FILES ONLY · MAX 20 MB</span>
            </div>
            <label className={`drop-zone ${file ? "has-file" : ""}`} htmlFor="email-file">
              <input id="email-file" type="file" accept=".eml,message/rfc822" onChange={e => setFile(e.target.files?.[0] || null)}/>
              <div className="upload-icon"><Upload size={23}/></div>
              <strong>{file ? file.name : "Select a suspicious email"}</strong>
              <span>{file ? `${(file.size / 1024).toFixed(1)} KB · Ready to analyze` : "Choose an .eml file from your computer"}</span>
              <span className="browse-link">{file ? "Choose another file" : "Browse files"}</span>
            </label>
            <div className="upload-actions">
              <span className="privacy-note"><ShieldCheck size={14}/> Local processing · Temporary upload is deleted after analysis</span>
              <button className="primary-button" onClick={analyze} disabled={!file || loading || !health}>
                {loading ? <><LoaderCircle className="spin" size={17}/> Analyzing email...</> : <><FileSearch size={17}/> Analyze email</>}
              </button>
            </div>
            {error && <div className="error-box"><XCircle size={16}/>{error}</div>}
          </section>

          {result && (
            <>
              <section className="result-heading">
                <div><div className="eyebrow">CASE {result.case_id}</div><h2>{result.email.subject || "Untitled email"}</h2><p>{result.email.sender} · {result.email.source_file}</p></div>
                <div className={`verdict-pill ${riskClass}`}>{verdict.replaceAll("_", " ")}</div>
              </section>

              <div className="result-tabs">
                {["overview", "evidence", "urls", "attachments"].map(t => (
                  <button key={t} className={tab === t ? "selected" : ""} onClick={() => setTab(t)}>{t[0].toUpperCase()+t.slice(1)}</button>
                ))}
              </div>

              {tab === "overview" && (
                <section className="result-grid">
                  <div className="panel score-panel">
                    <div className="panel-heading"><h3>Threat assessment</h3><span>TRIAGE SCORE</span></div>
                    <div className={`score-number ${riskClass}`}>{score}<small>/100</small></div>
                    <div className="score-track"><div className={`score-fill ${riskClass}`} style={{width: `${score}%`}}/></div>
                    <p className="muted">Deterministic indicator score. Not a probability of compromise.</p>
                    <div className="assessment-meta"><span>Assessment</span><strong>{verdict.replaceAll("_", " ")}</strong></div>
                    <div className="assessment-meta"><span>Confidence</span><strong>{result.assessment.confidence}</strong></div>
                  </div>
                  <div className="panel">
                    <div className="panel-heading"><h3>Finding summary</h3><span>{result.findings.length} FINDINGS</span></div>
                    <div className="severity-list">
                      {["critical","high","medium","low","info"].map(s => (
                        <div className="severity-row" key={s}><span className={`severity-dot ${s}`}/><span>{s}</span><strong>{result.findings.filter(f => f.severity === s).length}</strong></div>
                      ))}
                    </div>
                    <div className="summary-bottom"><span>URLs: {result.urls.length}</span><span>Attachments: {result.attachments.length}</span></div>
                  </div>
                </section>
              )}

              {tab === "evidence" && (
                <section className="panel evidence-panel">
                  <div className="panel-heading"><h3>Evidence and findings</h3><span>TRACEABLE INDICATORS</span></div>
                  {result.findings.length === 0 ? <p className="muted">No findings recorded.</p> : result.findings.map((f,i) => (
                    <article className="finding" key={i}>
                      <div className="finding-top"><span className={`severity-tag ${f.severity}`}>{f.severity}</span><span className="category">{f.category}</span></div>
                      <strong>{f.indicator}</strong><p>{f.explanation}</p>
                      {f.evidence && <code>{f.evidence}</code>}
                    </article>
                  ))}
                </section>
              )}

              {tab === "urls" && (
                <section className="panel evidence-panel">
                  <div className="panel-heading"><h3>Extracted URLs</h3><span>{result.urls.length} URLS</span></div>
                  {result.urls.length === 0 ? <p className="muted">No URLs extracted.</p> : result.urls.map((u,i) => (
                    <article className="finding" key={i}>
                      <strong><Globe size={15}/> {u.domain || "Unknown domain"}</strong>
                      <code>{u.original_url}</code>
                      {u.indicators.map((indicator,j) => <span className="indicator-chip" key={j}>{indicator}</span>)}
                    </article>
                  ))}
                  <p className="muted">URLs are inspected statically. MailSleuth does not open them.</p>
                </section>
              )}

              {tab === "attachments" && (
                <section className="panel evidence-panel">
                  <div className="panel-heading"><h3>Attachment analysis</h3><span>{result.attachments.length} FILES</span></div>
                  {result.attachments.length === 0 ? <p className="muted">No attachments detected.</p> : result.attachments.map((a,i) => (
                    <article className="finding" key={i}>
                      <strong><FileText size={15}/> {a.filename}</strong>
                      <p>Size: {a.size.toLocaleString()} bytes · Signature: {a.detected_signature}</p>
                      <code>SHA-256: {a.sha256}</code>
                      {a.findings.map((f,j) => <span className={`severity-tag ${f.severity}`} key={j}>{f.indicator}</span>)}
                    </article>
                  ))}
                  <p className="muted">Attachments are never executed by this application.</p>
                </section>
              )}

              <section className="report-actions">
                <div><strong>Investigation reports</strong><span>Download the generated case evidence.</span></div>
                <a href={`${API}/api/reports/${result.case_id}/json`}><Download size={15}/> JSON</a>
                <a href={`${API}/api/reports/${result.case_id}/markdown`}><Download size={15}/> Markdown</a>
              </section>
              <section className="limitations"><AlertTriangle size={16}/><div><strong>Analyst note</strong><p>{result.assessment.limitations.join(" ")}</p></div></section>
            </>
          )}

          <section className="cases-panel">
            <div className="section-title">
              <div><div className="eyebrow">INVESTIGATION RECORDS</div><h2>Recent cases</h2></div>
              <button className="text-button" onClick={loadData}><RefreshCw size={14}/> Refresh</button>
            </div>
            {cases.length === 0 ? (
              <div className="empty-state"><History size={25}/><strong>No cases recorded</strong><span>Upload an EML file to start your first investigation.</span></div>
            ) : (
              <div className="table-wrap"><table>
                <thead><tr><th>CASE</th><th>SUBJECT / SOURCE</th><th>SENDER</th><th>VERDICT</th><th>SCORE</th><th></th></tr></thead>
                <tbody>{cases.map(c => (
                  <tr key={c.case_id}>
                    <td className="mono">{c.case_id}</td>
                    <td><strong>{c.subject || c.source_file}</strong><small>{c.source_file}</small></td>
                    <td>{c.sender}</td>
                    <td><span className={`table-verdict ${c.verdict === "HIGH_RISK" ? "danger" : c.verdict === "SUSPICIOUS" ? "warning" : "safe"}`}>{c.verdict.replaceAll("_"," ")}</span></td>
                    <td className="mono">{c.risk_score}/100</td>
                    <td><button className="open-button" onClick={() => openCase(c.case_id)}>Open <ArrowUpRight size={13}/></button></td>
                  </tr>
                ))}</tbody>
              </table></div>
            )}
          </section>
          <footer>MailSleuth v1.0.0 <span>Local-first email forensics · Analyst-assisted triage</span></footer>
        </div>
      </main>
    </div>
  );
}

export default App;
TSX

cat > frontend/src/style.css <<'CSS'
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Sans:wght@400;500;600;700;800&display=swap');

:root{font-family:"DM Sans",sans-serif;color:#e7edf7;background:#090d16;font-synthesis:none;text-rendering:optimizeLegibility}
*{box-sizing:border-box}
body{margin:0;min-width:320px;background:#090d16}
button,input{font:inherit}
button{cursor:pointer}
.app-shell{min-height:100vh}
.sidebar{width:248px;position:fixed;inset:0 auto 0 0;background:#0d1320;border-right:1px solid #1c2738;padding:25px 16px;display:flex;flex-direction:column;z-index:2}
.brand{display:flex;align-items:center;gap:12px;padding:0 9px 34px}
.brand-icon{width:39px;height:39px;border-radius:11px;background:#123c52;color:#54d4e9;display:grid;place-items:center}
.brand strong{display:block;font-size:16px;letter-spacing:.2px}
.brand small{display:block;color:#71829b;font-size:9px;letter-spacing:1.6px;margin-top:3px}
.side-label,.eyebrow{font-size:10px;letter-spacing:1.45px;font-weight:700;color:#73839c}
.side-label{padding:0 10px 11px}
.nav-item{height:42px;border:0;background:transparent;color:#98a8bf;display:flex;align-items:center;gap:11px;padding:0 11px;border-radius:7px;text-align:left;font-size:12px;margin-bottom:4px}
.nav-item.active{background:#152a3b;color:#66d4e7}
.history-label{margin-top:34px}
.case-nav{overflow:auto}
.case-nav-item{width:100%;display:flex;align-items:flex-start;gap:10px;background:none;border:0;text-align:left;padding:10px 9px;color:#c4cede;border-radius:6px}
.case-nav-item:hover,.nav-item:hover{background:#172337}
.case-nav-text{font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:180px}
.case-nav-text small{display:block;color:#71819a;font:10px "DM Mono",monospace;margin-top:4px}
.tiny-dot,.status-dot{width:7px;height:7px;border-radius:50%;background:#42c68a;flex:none;margin-top:4px}
.tiny-dot.red{background:#f16c78}.tiny-dot.yellow{background:#e7b75a}.tiny-dot.green{background:#42c68a}
.sidebar-bottom{margin-top:auto}
.local-card{display:flex;gap:10px;align-items:center;background:#111d2b;border:1px solid #203047;padding:12px;border-radius:8px}
.local-card strong{display:block;font-size:10px}.local-card small{display:block;color:#7d8ca2;font-size:10px;margin-top:4px}
.status-dot.online{background:#43cb91;box-shadow:0 0 8px #43cb9180}.status-dot.offline{background:#e46c77}
.version{display:block;text-align:center;color:#65758c;font-size:9px;letter-spacing:1px;margin-top:15px}
.main{margin-left:248px;min-height:100vh}
.topbar{height:62px;border-bottom:1px solid #1c2738;display:flex;align-items:center;justify-content:space-between;padding:0 35px;background:#0b111d}
.breadcrumbs{display:flex;align-items:center;gap:8px;color:#7889a1;font-size:11px}.breadcrumbs strong{color:#d9e2ef}
.top-right{display:flex;align-items:center;gap:15px}
.connection{font-size:9px;letter-spacing:1px;display:flex;align-items:center;gap:7px;color:#8da0b8}
.connection .status-dot{width:6px;height:6px;margin:0}.connected .status-dot{background:#45c88e}.disconnected .status-dot{background:#e46c77}
.icon-button{border:1px solid #28364b;background:#111a29;color:#9cacc1;border-radius:7px;width:31px;height:31px;display:grid;place-items:center}
.content{max-width:1450px;margin:auto;padding:32px 35px 22px}
.page-heading{display:flex;justify-content:space-between;align-items:flex-end;margin-bottom:25px}
h1{font-size:26px;letter-spacing:-.8px;margin:8px 0 5px}h2{font-size:17px;margin:5px 0 0;letter-spacing:-.3px}
.page-heading p,.result-heading p{color:#8797ad;font-size:12px;margin:0}
.heading-chip{border:1px solid #214052;color:#70cddd;border-radius:20px;padding:8px 12px;font-size:10px;display:flex;align-items:center;gap:7px}
.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:13px;margin-bottom:19px}
.stat-card{background:#101927;border:1px solid #202e42;border-radius:9px;padding:16px;display:grid;grid-template-columns:39px 1fr;column-gap:11px;align-items:center}
.stat-icon{width:36px;height:36px;border-radius:8px;display:grid;place-items:center}.stat-icon svg{width:17px}.stat-icon.blue{background:#152f48;color:#64b8ed}.stat-icon.red{background:#3a202d;color:#f17d8a}.stat-icon.yellow{background:#3a3020;color:#e9bd67}.stat-icon.green{background:#17352d;color:#5bd5a0}
.stat-card span{font-size:10px;color:#8c9bb0}.stat-card strong{font-size:21px;display:block;margin-top:2px}.stat-card>small{grid-column:2;color:#65768e;font-size:9px;margin-top:7px}
.upload-panel,.panel,.cases-panel{background:#101927;border:1px solid #202e42;border-radius:10px;padding:20px}
.section-title{display:flex;align-items:center;justify-content:space-between;margin-bottom:17px}
.file-limit,.panel-heading>span{color:#6f829c;font:9px "DM Mono",monospace;letter-spacing:.7px}
.drop-zone{border:1px dashed #3a4d65;border-radius:9px;background:#0d1624;min-height:145px;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:7px;cursor:pointer;transition:.2s}
.drop-zone:hover,.drop-zone.has-file{border-color:#42aabe;background:#102130}
.drop-zone input{display:none}
.upload-icon{color:#63c6db;background:#173448;width:39px;height:39px;border-radius:10px;display:grid;place-items:center;margin-bottom:2px}
.drop-zone strong{font-size:12px}.drop-zone>span{font-size:10px;color:#8293aa}.drop-zone .browse-link{color:#65cde0;font-weight:700}
.upload-actions{display:flex;align-items:center;justify-content:space-between;margin-top:15px}
.privacy-note{display:flex;align-items:center;gap:7px;color:#8294a9;font-size:10px}
.privacy-note svg{color:#56c99a}
.primary-button{border:0;background:#1e9ab0;color:white;border-radius:7px;padding:10px 15px;display:flex;align-items:center;gap:8px;font-size:11px;font-weight:700}
.primary-button:hover{background:#27aec4}.primary-button:disabled{opacity:.4;cursor:not-allowed}
.error-box{margin-top:12px;color:#ff9ba4;background:#351d28;border:1px solid #63303e;padding:10px;border-radius:6px;font-size:11px;display:flex;gap:8px;align-items:center}
.result-heading{display:flex;align-items:center;justify-content:space-between;margin:27px 0 14px}.result-heading h2{font-size:19px;margin:6px 0}.result-heading p{margin-top:5px}
.verdict-pill,.table-verdict,.severity-tag{border-radius:5px;padding:6px 9px;font-size:9px;font-weight:700;letter-spacing:.5px}
.danger{color:#ff8995!important}.verdict-pill.danger,.table-verdict.danger,.severity-tag.high,.severity-tag.critical{background:#3a202b;color:#ff8d99}
.warning{color:#eac16e!important}.verdict-pill.warning,.table-verdict.warning,.severity-tag.medium{background:#3a3020;color:#eac16e}
.safe{color:#66d7a4!important}.verdict-pill.safe,.table-verdict.safe,.severity-tag.low,.severity-tag.info{background:#173329;color:#66d7a4}
.result-tabs{display:flex;gap:4px;border-bottom:1px solid #26354a;margin-bottom:14px}
.result-tabs button{border:0;background:none;color:#8495ac;padding:11px 14px;font-size:11px;border-bottom:2px solid transparent}
.result-tabs button.selected{color:#66d1e2;border-bottom-color:#48b9cc}
.result-grid{display:grid;grid-template-columns:1fr 1fr;gap:13px}
.panel-heading{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}.panel-heading h3{font-size:13px;margin:0}
.score-number{font-size:48px;font-weight:800;letter-spacing:-2px;margin:14px 0}.score-number small{font-size:15px;color:#75869d;letter-spacing:0;margin-left:4px}
.score-track{height:7px;background:#253247;border-radius:10px;overflow:hidden}.score-fill{height:100%;border-radius:10px}.score-fill.danger{background:#e66b7b}.score-fill.warning{background:#d6a64f}.score-fill.safe{background:#48bd8a}
.muted{font-size:10px;color:#8191a7;line-height:1.6}
.assessment-meta{display:flex;justify-content:space-between;border-top:1px solid #243247;padding:10px 0;font-size:10px}.assessment-meta span{color:#8191a7}
.severity-row{display:flex;align-items:center;gap:9px;padding:8px 0;color:#a9b6c8;font-size:11px;text-transform:capitalize}.severity-row strong{margin-left:auto;color:#e6edf6}
.severity-dot{width:7px;height:7px;border-radius:50%;background:#71839a}.severity-dot.critical,.severity-dot.high{background:#ec7180}.severity-dot.medium{background:#e8bd65}.severity-dot.low{background:#53c99a}.severity-dot.info{background:#6e9acb}
.summary-bottom{border-top:1px solid #243247;padding-top:12px;display:flex;gap:18px;color:#8595aa;font-size:10px}
.evidence-panel{margin-top:0}.finding{border-top:1px solid #253247;padding:14px 0;display:flex;flex-direction:column;align-items:flex-start;gap:7px}.finding:first-of-type{border-top:0}
.finding-top{display:flex;gap:9px;align-items:center}.finding>strong{font-size:12px;display:flex;align-items:center;gap:7px}.finding p{font-size:10px;color:#9ba9bb;margin:0;line-height:1.5}.finding code{font:10px "DM Mono",monospace;color:#b8c7d9;background:#0a111c;border:1px solid #26354a;border-radius:5px;padding:8px;max-width:100%;overflow-wrap:anywhere}
.category{font-size:9px;color:#8292a8;text-transform:uppercase;letter-spacing:1px}.indicator-chip{font-size:9px;background:#332b20;color:#e6bd6e;padding:5px 8px;border-radius:4px}
.report-actions{display:flex;align-items:center;gap:9px;margin-top:13px;padding:15px 17px;border:1px solid #26354a;border-radius:8px;background:#111c2a}
.report-actions>div{margin-right:auto}.report-actions strong,.report-actions span{display:block}.report-actions strong{font-size:11px}.report-actions span{font-size:9px;color:#8191a7;margin-top:4px}
.report-actions a{display:flex;align-items:center;gap:6px;text-decoration:none;color:#70cddd;border:1px solid #2a4b5a;border-radius:6px;padding:8px 10px;font-size:10px}
.limitations{display:flex;gap:10px;padding:13px 15px;margin-top:10px;background:#29251b;border:1px solid #51442b;border-radius:7px;color:#d7b56f}.limitations strong{font-size:10px}.limitations p{font-size:10px;line-height:1.5;margin:4px 0 0;color:#b9a77f}
.cases-panel{margin-top:23px}.text-button{border:0;background:none;color:#67cddd;font-size:10px;display:flex;align-items:center;gap:6px}
.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;text-align:left;white-space:nowrap}th{font:9px "DM Mono",monospace;color:#72849c;letter-spacing:.8px;padding:11px 10px;border-bottom:1px solid #28374c}td{font-size:10px;color:#a9b7c9;padding:13px 10px;border-bottom:1px solid #202e42}td strong{display:block;color:#dbe4f0;font-size:10px}td small{display:block;color:#72839a;margin-top:4px;font-size:9px}.mono{font-family:"DM Mono",monospace;font-size:9px}.open-button{display:flex;align-items:center;gap:4px;background:none;border:0;color:#68cddd;font-size:10px}
.empty-state{display:flex;flex-direction:column;align-items:center;gap:9px;padding:30px;color:#74869e}.empty-state strong{font-size:12px;color:#b7c4d5}.empty-state span,.empty-small{font-size:10px;color:#75869c}.empty-small{padding-left:10px}
footer{display:flex;justify-content:space-between;padding:23px 2px 5px;color:#667790;font-size:9px}
.spin{animation:spin 1s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}
@media(max-width:1050px){.sidebar{width:205px}.main{margin-left:205px}.content{padding:25px 20px}.stats-grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:720px){.sidebar{position:relative;width:100%;height:auto;padding:14px}.brand{padding-bottom:10px}.sidebar .side-label,.sidebar .nav-item,.sidebar .case-nav,.sidebar-bottom{display:none}.main{margin-left:0}.topbar{padding:0 15px}.content{padding:22px 13px}.page-heading{align-items:flex-start;gap:10px;flex-direction:column}.stats-grid{grid-template-columns:1fr 1fr;gap:8px}.stat-card{padding:11px}.result-grid{grid-template-columns:1fr}.upload-actions{align-items:flex-start;gap:12px;flex-direction:column}.report-actions{flex-wrap:wrap}.report-actions>div{width:100%}.heading-chip{display:none}footer{gap:12px;flex-direction:column}}
CSS

# ---------------- IGNORE LOCAL ARTIFACTS ----------------

cat >> .gitignore <<'EOF'

# MailSleuth local runtime
data/*.log
data/*.pid
frontend/node_modules/
frontend/dist/
EOF

# ---------------- INSTALL ----------------

if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv .venv
fi

.venv/bin/python -m pip install fastapi "uvicorn[standard]" python-multipart

cd frontend
npm install
npm run build
cd "$ROOT"

# ---------------- START BOTH SERVICES ----------------

cat > start_mailsleuth.sh <<'START'
#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$ROOT/data"

if [[ -f "$ROOT/data/api.pid" ]] && kill -0 "$(cat "$ROOT/data/api.pid")" 2>/dev/null; then
  echo "MailSleuth API already running."
else
  nohup "$ROOT/.venv/bin/python" -m uvicorn mailsleuth.api:app \
    --app-dir "$ROOT/src" --host 127.0.0.1 --port 8000 \
    > "$ROOT/data/api.log" 2>&1 < /dev/null &
  echo $! > "$ROOT/data/api.pid"
fi

if [[ -f "$ROOT/data/frontend.pid" ]] && kill -0 "$(cat "$ROOT/data/frontend.pid")" 2>/dev/null; then
  echo "MailSleuth frontend already running."
else
  cd "$ROOT/frontend"
  nohup npm run dev -- --host 127.0.0.1 --port 5173 \
    > "$ROOT/data/frontend.log" 2>&1 < /dev/null &
  echo $! > "$ROOT/data/frontend.pid"
fi

echo "Starting MailSleuth services..."
for i in {1..20}; do
  if curl -fsS http://127.0.0.1:8000/api/health >/dev/null 2>&1 &&
     curl -fsS http://127.0.0.1:5173 >/dev/null 2>&1; then
    echo ""
    echo "MailSleuth is running."
    echo "Dashboard: http://127.0.0.1:5173"
    echo "API docs:  http://127.0.0.1:8000/docs"
    exit 0
  fi
  sleep 1
done

echo "Startup did not complete. Check data/api.log and data/frontend.log."
exit 1
START

cat > stop_mailsleuth.sh <<'STOP'
#!/usr/bin/env bash
ROOT="$(cd "$(dirname "$0")" && pwd)"
for service in api frontend; do
  pidfile="$ROOT/data/$service.pid"
  if [[ -f "$pidfile" ]]; then
    pid="$(cat "$pidfile")"
    kill "$pid" 2>/dev/null || true
    rm -f "$pidfile"
  fi
done
echo "Stop signal sent to MailSleuth services."
STOP

chmod +x start_mailsleuth.sh stop_mailsleuth.sh
./start_mailsleuth.sh
