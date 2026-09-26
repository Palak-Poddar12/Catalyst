import React, { useEffect, useState } from "react";
import { Mail, RefreshCw, ShieldCheck, ExternalLink, RotateCcw } from "lucide-react";
import { gmailAuth, gmailStatus, gmailSync } from "../api";
import { PageHeader, GlassCard, Section, StatusBadge, LoadingState, ErrorState } from "../components/ui";

export default function Gmail() {
  const [status, setStatus] = useState(null);
  const [busy, setBusy] = useState(false);
  const [syncState, setSyncState] = useState(null);
  const [err, setErr] = useState(null);

  async function load() {
    setErr(null);
    try { const r = await gmailStatus(); setStatus(r.data); } catch (e) { setErr(e); }
  }
  useEffect(() => { load(); }, []);

  async function connect() {
    setBusy(true); setErr(null);
    try { const r = await gmailAuth(); window.location.href = r.data.authorization_url; }
    catch (e) { setErr(e); setBusy(false); }
  }

  async function sync() {
    setBusy(true); setErr(null);
    try { const r = await gmailSync(); setSyncState(r.data); } catch (e) { setErr(e); } finally { setBusy(false); }
  }

  return <>
    <PageHeader eyebrow="INTEGRATIONS / GMAIL" title="Gmail Investigation" subtitle="Connect a mailbox through Google OAuth and send messages through the SatGuard investigation pipeline." actions={<button className="secondary" onClick={load}><RefreshCw size={16}/>Refresh</button>} />
    {err && <ErrorState error={err} />}
    {!status ? <LoadingState /> : <>
      <div className="integration-grid gmail-connect-grid">
        <GlassCard><span>OAuth status</span><strong>{status.connected ? "Connected" : "Not connected"}</strong><StatusBadge status={status.connected ? "CONNECTED" : "READY"} /></GlassCard>
        <GlassCard><span>Connected account</span><strong>{status.email || "—"}</strong><small>Google OAuth read access</small></GlassCard>
        <GlassCard><span>Inbox analysis</span><strong>Threat triage</strong><small>Raw messages → forensics → risk</small></GlassCard>
      </div>
      <Section title="Mailbox connection" subtitle="Google handles authentication; SatGuard receives authorized Gmail API access.">
        <GlassCard className="gmail-connect-card">
          <div className="gmail-connect-icon"><Mail size={25}/></div>
          <div><div className="eyebrow">SECURE GOOGLE OAUTH</div><h3>{status.connected ? "Mailbox connected" : "Connect your Gmail"}</h3><p>{status.connected ? "The mailbox is ready for threat triage and investigation." : "Authorize SatGuard to read messages for security analysis. Your Gmail password is never entered into SatGuard."}</p></div>
          <div className="gmail-connect-actions">{status.connected ? <><button className="primary" onClick={sync} disabled={busy}><ShieldCheck size={16}/>{busy ? "Starting sync…" : "Sync & analyze inbox"}</button><button className="secondary" onClick={load}><RotateCcw size={16}/>Refresh status</button></> : <button className="primary" onClick={connect} disabled={busy}><ExternalLink size={16}/>{busy ? "Opening Google…" : "Connect Gmail"}</button>}</div>
        </GlassCard>
      </Section>
      {syncState && <Section title="Sync activity" subtitle="Mailbox messages are submitted to the same forensic pipeline used for uploaded EML evidence."><GlassCard><div className="sync-status"><StatusBadge status={syncState.status || "QUEUED"}/><span>Job ID: {syncState.job_id || "—"}</span><b>{syncState.synced?.length || 0} processed</b></div></GlassCard></Section>}
    </>}
  </>;
}
