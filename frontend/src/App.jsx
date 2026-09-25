import {Routes,Route,NavLink,useLocation,useNavigate} from 'react-router-dom';
import {AuthProvider,useAuth} from './auth/AuthContext';
import Protected from './components/Protected';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import AnalyzeEmail from './pages/AnalyzeEmail';
import GmailIngestion from './pages/GmailIngestion';
import CasesList from './pages/CasesList';
import CaseDetail from './pages/CaseDetail';
import ThreatIntel from './pages/ThreatIntel';
import ThreatMap from './pages/ThreatMap';
import Reports from './pages/Reports';
import AdvancedIntelligence from './pages/AdvancedIntelligence';

const items=[
 ['/','Dashboard','⌂'],['/analyze','Analyze Email','＋'],['/gmail','Connect Gmail','✉'],
 ['/cases','Investigations','▣'],['/map','Threat Map','◎'],['/intel','IOC Intelligence','⌕'],
 ['/intelligence','Intelligence Lab','✦'],['/reports','Forensic Reports','▤']
];

function Shell({children}){
 const {user,signOut}=useAuth(); const loc=useLocation(); const nav=useNavigate();
 const label=items.find(x=>loc.pathname===x[0])?.[1]||(loc.pathname.startsWith('/cases/')?'Case Investigation':'SatGuard');
 return <div className="app-shell">
  <div className="ambient ambient-one"/><div className="ambient ambient-two"/>
  <aside className="sidebar glass-panel">
   <div className="brand">
    <div className="brand-mark"><span>S</span></div><div><div className="brand-name">SatGuard</div><div className="brand-sub">Email Forensic Intelligence</div></div>
   </div>
   <div className="side-label">SECURITY OPERATIONS</div>
   <nav>{items.map(([to,l,i])=><NavLink key={to} to={to} end={to==='/' } className={({isActive})=>`nav-link ${isActive?'active':''}`}><span className="nav-icon">{i}</span><span>{l}</span></NavLink>)}</nav>
   <div className="sidebar-bottom">
    <div className="system-pill"><span className="dot ok"/> All systems operational</div>
    <div className="user-mini"><div className="avatar">{(user.name||'U').slice(0,1).toUpperCase()}</div><div><b>{user.name}</b><span>{user.role}</span></div></div>
    <button className="logout" onClick={()=>{signOut();nav('/login')}}>Sign out <span>↗</span></button>
    <div className="ps">SIH26106 · FINAL SUBMISSION BUILD</div>
   </div>
  </aside>
  <main className="main">
   <header className="topbar glass-panel">
    <div><div className="eyebrow">SECURITY OPERATIONS CENTER <span className="live-dot"/> LIVE</div><h1>{label}</h1><p>AI detection · forensic reconstruction · infrastructure intelligence · evidence</p></div>
    <div className="header-actions"><span className="product-tag"><span className="status-ring"/> {user.role}</span><button className="profile-btn" onClick={()=>nav('/')} aria-label="Open dashboard">{(user.name||'U').slice(0,1).toUpperCase()}</button></div>
   </header>
   <div className="page-content">{children}</div>
  </main>
 </div>
}

function App(){return <AuthProvider><Routes><Route path="/login" element={<Login/>}/><Route path="*" element={<Protected><Shell><Routes>
 <Route path="/" element={<Dashboard/>}/><Route path="/analyze" element={<AnalyzeEmail/>}/><Route path="/gmail" element={<GmailIngestion/>}/><Route path="/cases" element={<CasesList/>}/><Route path="/cases/:caseId" element={<CaseDetail/>}/><Route path="/map" element={<ThreatMap/>}/><Route path="/intel" element={<ThreatIntel/>}/><Route path="/intelligence" element={<AdvancedIntelligence/>}/><Route path="/reports" element={<Reports/>}/>
 </Routes></Shell></Protected>}/></Routes></AuthProvider>}
export default App;
