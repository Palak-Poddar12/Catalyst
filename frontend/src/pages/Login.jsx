import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Shield, Eye, EyeOff, Wifi, ArrowRight, CheckCircle2, ScanSearch, Network, Fingerprint } from "lucide-react";
import { DEMO_ACCOUNTS, authenticateLocal, getRememberedLogin, saveRememberedLogin, clearRememberedLogin, saveSession } from "../utils/auth";

const demos = Object.values(DEMO_ACCOUNTS);

export default function Login() {
  const nav = useNavigate();
  const remembered = getRememberedLogin();
  const [email, setEmail] = useState(remembered?.email || "");
  const [password, setPassword] = useState(remembered?.password || "");
  const [show, setShow] = useState(false);
  const [remember, setRemember] = useState(Boolean(remembered));
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  function selectDemo(account) {
    setEmail(account.email);
    setPassword(account.password);
    setErr("");
  }

  function submit(e) {
    e.preventDefault();
    setBusy(true);
    setErr("");
    window.setTimeout(() => {
      const session = authenticateLocal(email, password);
      if (!session) {
        setErr("Invalid username or password. Select a Demo Account or use the configured prototype credentials.");
        setBusy(false);
        return;
      }
      if (remember) saveRememberedLogin(email, password);
      else clearRememberedLogin();
      saveSession(session, remember);
      setBusy(false);
      nav("/dashboard", { replace: true });
    }, 250);
  }

  return (
    <div className="login-page app-bg">
      <div className="login-glow" />
      <div className="login-card">
        <section className="login-hero">
          <div className="hero-kicker">SATGUARD / SECURITY OPERATIONS</div>
          <h1>Investigate.<br />Correlate.<br />Secure.</h1>
          <p>AI-powered email threat intelligence and digital-forensics workspace for analysts who need evidence, context and action in one place.</p>
          <div className="hero-points">
            <span className="hero-point"><ScanSearch size={13} /> Email forensics</span>
            <span className="hero-point"><Network size={13} /> Infrastructure graph</span>
            <span className="hero-point"><Fingerprint size={13} /> Evidence integrity</span>
          </div>
        </section>

        <section className="login-panel">
          <div className="login-brand">
            <div className="brand-mark big"><Shield size={27} /></div>
            <div>
              <b>SATGUARD</b>
              <span>Email Threat Intelligence &amp; Forensics</span>
            </div>
          </div>

          <div className="login-title">
            <span className="eyebrow">SECURE SOC ACCESS</span>
            <h1>Welcome to SatGuard</h1>
            <p>Sign in to investigate and secure your email infrastructure.</p>
          </div>

          <form onSubmit={submit} className="login-form">
            <label>
              Email
              <input value={email} onChange={(e) => setEmail(e.target.value)} type="email" autoComplete="username" placeholder="analyst@organization.local" required />
            </label>
            <label>
              Password
              <div className="password">
                <input value={password} onChange={(e) => setPassword(e.target.value)} type={show ? "text" : "password"} autoComplete="current-password" placeholder="••••••••" required />
                <button type="button" className="icon-btn" onClick={() => setShow(!show)} aria-label={show ? "Hide password" : "Show password"}>{show ? <EyeOff size={17} /> : <Eye size={17} />}</button>
              </div>
            </label>
            {err && <div className="login-error">{err}</div>}
            <div className="login-options">
              <label className="check"><input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} /> Remember me</label>
              <button type="button" className="text-btn" onClick={() => setErr("Password recovery is disabled for the frontend-only prototype.")}>Forgot password?</button>
            </div>
            <button className="primary full" disabled={busy}>{busy ? "Authenticating…" : "Sign In"}<ArrowRight size={17} /></button>
          </form>

          <div className="demo-box">
            <div className="demo-head"><span>Demo Accounts</span><small>Prototype access</small></div>
            <div className="demo-grid">
              {demos.map((account) => (
                <button type="button" key={account.role} onClick={() => selectDemo(account)}>
                  <span>{account.role}</span><small>{account.email}</small>
                </button>
              ))}
            </div>
          </div>

          <div className="secure"><Wifi size={15} /><span>Frontend prototype authentication</span><CheckCircle2 size={14} /></div>
        </section>
      </div>
    </div>
  );
}
