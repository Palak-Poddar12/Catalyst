import React,{useEffect,useState} from 'react';
import {Routes,Route,Navigate,useLocation,useNavigate} from 'react-router-dom';
import {getSession,getToken,clearSession,roleOf} from './utils/auth';
import {can} from './utils/permissions';
import {AppShell,PermissionGate} from './components/layout';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Cases,{CaseDetail} from './pages/Cases';
import Investigation from './pages/Investigation';
import Intelligence from './pages/Intelligence';
import Admin from './pages/Admin';
import Reports from './pages/Reports';
import Gmail from './pages/Gmail';
import Profile from './pages/Profile';
import NewInvestigation from './pages/NewInvestigation';
function Protected({children,permission}){const s=getSession();if(!s||!getToken())return <Navigate to="/login" replace/>;if(permission&&!can(roleOf(s),permission))return <Navigate to="/dashboard" replace/>;return <AppShell session={s}>{children}</AppShell>}
export default function App(){return <Routes><Route path="/login" element={<Login/>}/><Route path="/" element={<Navigate to="/dashboard" replace/>}/><Route path="/dashboard" element={<Protected permission="dashboard:view"><Dashboard/></Protected>}/><Route path="/investigations/new" element={<Protected permission="email:upload"><NewInvestigation/></Protected>}/><Route path="/cases" element={<Protected permission="case:view"><Cases/></Protected>}/><Route path="/cases/:caseId" element={<Protected permission="case:view"><CaseDetail/></Protected>}/><Route path="/intelligence" element={<Protected permission="threatintel:view"><Intelligence/></Protected>}/><Route path="/reports" element={<Protected permission="report:view"><Reports/></Protected>}/><Route path="/gmail" element={<Protected permission="gmail:investigate"><Gmail/></Protected>}/><Route path="/admin/*" element={<Protected permission="users:manage"><Admin/></Protected>}/><Route path="/profile" element={<Protected><Profile/></Protected>}/><Route path="*" element={<Navigate to="/dashboard" replace/>}/></Routes>}
