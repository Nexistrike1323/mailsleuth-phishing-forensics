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
