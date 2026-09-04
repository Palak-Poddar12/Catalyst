import React, {useState} from "react";
import {createRoot} from "react-dom/client";
import "./style.css";

const API = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000/api/v1";

function App() {
  const [caseId, setCaseId] = useState("");
  const [analysisId, setAnalysisId] = useState("");
  const [analysis, setAnalysis] = useState(null);
  const [file, setFile] = useState(null);
  const [message, setMessage] = useState("");

  async function createCase(e) {
    e.preventDefault();
    const body = {
      title: e.target.title.value,
      name: e.target.name.value,
      description: e.target.description.value,
      severity: e.target.severity.value
    };
    const r = await fetch(`${API}/cases`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(body)
    });
    const data = await r.json();
    if (!r.ok) return setMessage(JSON.stringify(data));
    setCaseId(data.id);
    setMessage(`Case created: ${data.id}`);
  }

  async function upload() {
    if (!caseId || !file) return setMessage("Enter case ID and select an .eml file.");
    const fd = new FormData();
    fd.append("file", file);
    const r = await fetch(`${API}/emails/upload/${caseId}`, {method:"POST", body:fd});
    const data = await r.json();
    if (!r.ok) return setMessage(JSON.stringify(data));
    setAnalysisId(data.analysis_id);
    setMessage(`Analysis created: ${data.analysis_id}`);
  }

  async function loadAnalysis() {
    const r = await fetch(`${API}/analysis/${analysisId}`);
    const data = await r.json();
    if (!r.ok) return setMessage(JSON.stringify(data));
    setAnalysis(data);
  }

  return <main>
    <h1>SIH26106 Cybersecurity Forensics</h1>
    <p>React → FastAPI → Forensics + ML → PostgreSQL</p>

    <section>
      <h2>1. Create Case</h2>
      <form onSubmit={createCase}>
        <input name="title" placeholder="Title" required />
        <input name="name" placeholder="Case name" required />
        <input name="description" placeholder="Description" />
        <select name="severity"><option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option></select>
        <button>Create Case</button>
      </form>
      <input value={caseId} onChange={e=>setCaseId(e.target.value)} placeholder="Case ID" />
    </section>

    <section>
      <h2>2. Upload EML</h2>
      <input type="file" accept=".eml" onChange={e=>setFile(e.target.files[0])} />
      <button onClick={upload}>Analyze Email</button>
    </section>

    <section>
      <h2>3. Get Analysis</h2>
      <input value={analysisId} onChange={e=>setAnalysisId(e.target.value)} placeholder="Analysis ID" />
      <button onClick={loadAnalysis}>Load Analysis</button>
    </section>

    {message && <pre>{message}</pre>}

    {analysis && <section>
      <h2>Forensic Findings</h2>
      <div className="grid">
        <b>Classification: {analysis.classification}</b>
        <b>Risk: {analysis.risk_level} ({analysis.final_risk_score})</b>
        <b>ML status: {analysis.ml_status}</b>
        <b>ML confidence: {analysis.ml_confidence}</b>
        <b>Forensic score: {analysis.forensic_score}</b>
      </div>
      <h3>Email</h3>
      <pre>{JSON.stringify(analysis.email, null, 2)}</pre>
      <h3>Findings</h3>
      <pre>{JSON.stringify(analysis.findings, null, 2)}</pre>
      <h3>IOCs</h3>
      <pre>{JSON.stringify(analysis.iocs, null, 2)}</pre>
      <h3>Graph Data</h3>
      <pre>{JSON.stringify(analysis.graph, null, 2)}</pre>
    </section>}
  </main>
}

createRoot(document.getElementById("root")).render(<App />);
