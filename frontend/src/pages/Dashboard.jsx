import React,{useCallback,useEffect,useState} from 'react';
import {Activity,AlertOctagon,FileSearch,ShieldAlert,Network,Layers3,RefreshCw,Clock3} from 'lucide-react';
import {dashboardApi} from '../api/modules';
import {PageHeader,StatCard,GlassCard,Section,RiskBadge,StatusBadge,LoadingState,ErrorState,DataTable,EmptyState} from '../components/ui';

const riskOrder=['CRITICAL','HIGH','MEDIUM','LOW'];

function toCount(value){
  const n=Number(value);
  return Number.isFinite(n)?Math.max(0,Math.round(n)):0;
}

function Dashboard(){
  const [data,setData]=useState(null);
  const [err,setErr]=useState(null);
  const [refreshing,setRefreshing]=useState(false);

  const load=useCallback(async()=>{
    try{
      setRefreshing(true);
      setErr(null);
      const response=await dashboardApi.get();
      setData(response?.data||{});
    }catch(error){
      setErr(error);
    }finally{
      setRefreshing(false);
    }
  },[]);

  useEffect(()=>{load();},[load]);

  if(err){
    return <>
      <PageHeader eyebrow="SOC / OVERVIEW" title="Security Operations Center" subtitle="Real-time email threat intelligence and forensic monitoring." actions={<button className="secondary dashboard-refresh" onClick={load} disabled={refreshing}><RefreshCw size={14} className={refreshing?'spin':''}/>Retry</button>}/>
      <ErrorState error={err}/>
    </>;
  }

  if(!data) return <LoadingState/>;

  const k=data.kpis||data.metrics||{};
  const distribution=k.risk_distribution||{};
  const distributionPct=k.risk_distribution_percent||{};
  const recent=Array.isArray(data.recent_investigations)?data.recent_investigations:[];
  const iocs=Array.isArray(data.recent_iocs)?data.recent_iocs:[];
  const activity=Array.isArray(data.activity)?data.activity:[];
  const totalAnalyses=toCount(k.total_analyses??data.analyses);

  const stats=[
    ['Total Investigations',k.total_investigations??data.cases,FileSearch],
    ['Active Threats',k.active_threats??data.high_risk,ShieldAlert,'danger'],
    ['Critical Findings',k.critical_findings,AlertOctagon,'critical'],
    ['High Risk Emails',k.high_risk_emails??data.high_risk,Activity,'high'],
    ['IOCs Discovered',k.iocs_discovered,Network,'accent'],
    ['Campaigns Correlated',k.campaigns_correlated,Layers3,'violet'],
  ];

  return <>
    <PageHeader
      eyebrow="SOC / OVERVIEW"
      title="Security Operations Center"
      subtitle="Real-time email threat intelligence and forensic monitoring."
      actions={<div className="dashboard-head-actions"><span className="live-pill"><i/>LIVE TELEMETRY</span><button className="icon-btn dashboard-refresh" onClick={load} disabled={refreshing} title="Refresh dashboard" aria-label="Refresh dashboard"><RefreshCw size={15} className={refreshing?'spin':''}/></button></div>}
    />

    <div className="stats-grid">
      {stats.map(([label,value,Icon,tone])=><StatCard key={label} label={label} value={toCount(value)} icon={Icon} tone={tone}/>) }
    </div>

    <div className="dashboard-grid">
      <Section title="Threat Overview" subtitle={`${totalAnalyses} analyzed email${totalAnalyses===1?'':'s'}`}>
        <GlassCard className="risk-overview">
          {riskOrder.map(level=>{
            const count=toCount(distribution[level.toLowerCase()]);
            const percent=Math.max(0,Math.min(100,Number(distributionPct[level.toLowerCase()]??(totalAnalyses?(count/totalAnalyses)*100:0))||0));
            return <div className="risk-row" key={level}>
              <RiskBadge level={level}/>
              <div className="risk-track"><span style={{width:`${percent}%`}}/></div>
              <b>{count}</b>
            </div>;
          })}
        </GlassCard>
      </Section>

      <Section title="Investigation Activity" subtitle="Investigations created over the last 7 days">
        <GlassCard className="activity-chart">
          {activity.length?<div className="bars dashboard-bars">
            {activity.map((item,index)=>{
              const value=toCount(item.value??item.count);
              const max=Math.max(1,...activity.map(x=>toCount(x.value??x.count)));
              const height=value?Math.max(10,(value/max)*100):5;
              return <div key={`${item.label||index}-${index}`} className="bar-col">
                <b>{value}</b>
                <span style={{height:`${height}%`}} title={`${value} investigation${value===1?'':'s'}`}/>
                <small>{item.label||index+1}</small>
              </div>;
            })}
          </div>:<EmptyState title="No investigation activity" text="Create or ingest an investigation to populate this activity view."/>}
        </GlassCard>
      </Section>
    </div>

    <div className="dashboard-grid lower">
      <Section title="Recent Investigations" subtitle={`${recent.length} latest case${recent.length===1?'':'s'}`}>
        {recent.length?<DataTable rows={recent} columns={[
          {key:'case_id',label:'Case ID'},
          {key:'subject',label:'Subject'},
          {key:'sender',label:'Sender'},
          {key:'risk_level',label:'Risk',render:r=><RiskBadge level={r.risk_level||r.risk||'LOW'}/>} ,
          {key:'classification',label:'Classification'},
          {key:'status',label:'Status',render:r=><StatusBadge status={r.status||'PENDING'}/>} ,
          {key:'updated_at',label:'Updated',render:r=>r.updated_at?new Date(r.updated_at).toLocaleString(): '—'}
        ]}/>:<GlassCard className="dashboard-empty"><EmptyState title="No investigations yet" text="Create a new investigation or sync a Gmail message to populate this section."/></GlassCard>}
      </Section>

      <Section title="Threat Intelligence" subtitle={`${iocs.length} latest indicator${iocs.length===1?'':'s'}`}>
        {iocs.length?<DataTable rows={iocs} columns={[
          {key:'type',label:'Type'},
          {key:'value',label:'Indicator'},
          {key:'risk',label:'Risk',render:r=><RiskBadge level={r.risk||'LOW'}/>} ,
          {key:'confidence',label:'Confidence',render:r=>r.confidence==null?'—':`${Math.round(Number(r.confidence)*100)}%`}
        ]}/>:<GlassCard className="dashboard-empty"><EmptyState title="No indicators yet" text="IOCs extracted from analyzed emails will appear here."/></GlassCard>}
      </Section>
    </div>

    <div className="dashboard-footnote"><Clock3 size={13}/>Dashboard data is calculated from persisted cases, analyses, findings and IOCs.</div>
  </>;
}

export default Dashboard;
