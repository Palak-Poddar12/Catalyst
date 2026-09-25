import { Routes, Route, NavLink, useLocation, useNavigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './auth/AuthContext';
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

const items = [
  ['/', 'Overview', '⌂'],
  ['/analyze', 'Analyze email', '↳'],
  ['/gmail', 'Gmail intake', '✉'],
  ['/cases', 'Investigations', '▤'],
  ['/map', 'Threat map', '◎'],
  ['/intel', 'IOC intelligence', '⌕'],
  ['/intelligence', 'Intelligence lab', '✦'],
  ['/reports', 'Reports', '▧'],
];

function Shell({ children }) {
  const { user, signOut } = useAuth();
  const loc = useLocation();
  const nav = useNavigate();
  const title = items.find(([to]) => loc.pathname === to)?.[1] || (loc.pathname.startsWith('/cases/') ? 'Case investigation' : 'SatGuard');

  return (
    <div className="product-shell">
      <aside className="sidebar">
        <div className="brand-row">
          <div className="brand-symbol">S</div>
          <div><strong>SatGuard</strong><span>EMAIL FORENSIC PLATFORM</span></div>
        </div>

        <div className="workspace-select">
          <span className="workspace-dot" /> Security Operations
          <span className="chevron">⌄</span>
        </div>

        <div className="nav-heading">WORKSPACE</div>
        <nav className="product-nav">
          {items.map(([to, label, icon]) => (
            <NavLink key={to} to={to} end={to === '/'} className={({ isActive }) => `product-nav-link ${isActive ? 'active' : ''}`}>
              <span className="nav-glyph">{icon}</span><span>{label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-spacer" />
        <div className="sidebar-status"><span className="status-dot" /> All systems operational</div>
        <div className="account-row">
          <div className="account-avatar">{(user?.name || 'U').slice(0, 1).toUpperCase()}</div>
          <div className="account-copy"><strong>{user?.name || 'Analyst'}</strong><span>{user?.role || 'analyst'}</span></div>
          <button className="icon-button" onClick={() => { signOut(); nav('/login'); }} title="Sign out">↗</button>
        </div>
      </aside>

      <main className="workspace">
        <header className="workspace-header">
          <div className="breadcrumbs"><span>SatGuard</span><b>/</b><strong>{title}</strong></div>
          <div className="header-tools">
            <div className="system-live"><span className="status-dot" /> Live</div>
            <button className="header-icon" title="Notifications">♢<i /></button>
            <button className="profile-chip" onClick={() => nav('/')}><span>{(user?.name || 'U').slice(0, 1).toUpperCase()}</span>{user?.name || 'Analyst'}</button>
          </div>
        </header>
        <section className="workspace-body">{children}</section>
      </main>
    </div>
  );
}

function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="*" element={<Protected><Shell><Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/analyze" element={<AnalyzeEmail />} />
          <Route path="/gmail" element={<GmailIngestion />} />
          <Route path="/cases" element={<CasesList />} />
          <Route path="/cases/:caseId" element={<CaseDetail />} />
          <Route path="/map" element={<ThreatMap />} />
          <Route path="/intel" element={<ThreatIntel />} />
          <Route path="/intelligence" element={<AdvancedIntelligence />} />
          <Route path="/reports" element={<Reports />} />
        </Routes></Shell></Protected>} />
      </Routes>
    </AuthProvider>
  );
}

export default App;
