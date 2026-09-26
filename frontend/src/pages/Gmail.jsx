import React,{useEffect,useRef,useState} from 'react';
import {Mail,RefreshCw,ShieldCheck,ExternalLink} from 'lucide-react';
import {gmailApi} from '../api/modules';
import {gmailAuth,gmailSync,gmailSyncStatus} from '../api';
import {PageHeader,GlassCard,Section,StatusBadge,DataTable,LoadingState,ErrorState,EmptyState,RiskBadge} from '../components/ui';

export default function Gmail(){
  const [status,setStatus]=useState(null),[job,setJob]=useState(null),[err,setErr]=useState(null),[busy,setBusy]=useState(false);
  const timer=useRef(null);
  const load=()=>gmailApi.status().then(r=>setStatus(r.data)).catch(setErr);
  useEffect(()=>{load(); return()=>{if(timer.current)clearInterval(timer.current)}},[]);
  const connect=async()=>{setErr(null);try{const r=await gmailAuth();window.location.href=r.data?.authorization_url||r.url}catch(e){setErr(e)}};
  const sync=async()=>{
    setErr(null);setBusy(true);setJob(null);
    try{
      const x=await gmailSync(10);setJob(x);
      timer.current=setInterval(async()=>{
        try{const next=await gmailSyncStatus(x.job_id);setJob(next);if(next.status==='completed'||next.status==='failed'){clearInterval(timer.current);timer.current=null;setBusy(false)}}
        catch(e){clearInterval(timer.current);timer.current=null;setBusy(false);setErr(e)}
      },1200);
    }catch(e){setBusy(false);setErr(e)}
  };
  const rows=job?.synced||[];
  return <>
    <PageHeader eyebrow="INTEGRATIONS / GMAIL" title="Gmail Investigation" subtitle="Connect a real Gmail mailbox, ingest recent messages, and send them through the same forensic pipeline." actions={<button className="secondary" onClick={load}><RefreshCw size={16}/>Refresh</button>}/>
    {err&&<ErrorState error={err}/>} 
    {!status?<LoadingState/>:<>
      <div className="integration-grid">
        <GlassCard><span>OAuth status</span><strong>{status.connected?'Connected':'Not connected'}</strong></GlassCard>
        <GlassCard><span>Connected account</span><strong>{status.email||'—'}</strong></GlassCard>
        <GlassCard><span>Last sync</span><strong>{job?.status?job.status.toUpperCase():'Not run'}</strong></GlassCard>
        <GlassCard><span>Messages processed</span><strong>{job?.count??rows.length}</strong></GlassCard>
      </div>
      <GlassCard className="integration-actions">
        {status.connected ? <button className="primary" onClick={sync} disabled={busy}><RefreshCw size={17} className={busy?'spin':''}/>{busy?'Syncing Gmail…':'Sync Gmail Messages'}</button> : <button className="primary" onClick={connect}><Mail size={17}/>Connect Gmail</button>}
        {job?.status==='running'&&<span>Fetching messages and running forensic + ML analysis. Keep this page open.</span>}
        {job?.status==='completed'&&<span><ShieldCheck size={16}/> Sync completed. Open <a href="/cases">Investigations</a> to inspect the Gmail case.</span>}
      </GlassCard>
      {job?.error&&<GlassCard className="integration-warning"><b>Sync failed</b><span>{job.error}</span></GlassCard>}
      <Section title="Synced Gmail Messages" subtitle="Real messages returned by Gmail and analyzed by SatGuard">
        {rows.length?<DataTable rows={rows} columns={[
          {key:'subject',label:'Subject',render:r=><b>{r.subject||'(No subject)'}</b>},
          {key:'sender',label:'Sender',render:r=><span className="mono">{r.sender||'—'}</span>},
          {key:'date',label:'Received'},
          {key:'classification',label:'Classification'},
          {key:'risk_level',label:'Risk',render:r=><RiskBadge level={r.risk_level}/>} ,
          {key:'analysis_id',label:'Analysis ID'},
          {key:'status',label:'Status',render:r=><StatusBadge status={r.status}/>} 
        ]}/>:<EmptyState title={status.connected?'Ready to sync your Gmail':'Connect Gmail first'} text={status.connected?'Tap “Sync Gmail Messages” to load real inbox messages into the investigation workflow.':'Authorize the mailbox before syncing.'}/>} 
      </Section>
    </>}
  </>
}
