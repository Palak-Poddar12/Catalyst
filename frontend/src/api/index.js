import {api} from './client';
export const getCases=()=>api('/cases');
export const createCase=(payload)=>api.post('/cases', payload).then((response) => response.data);
export const uploadEmail = (caseId, file) => {
  const fd = new FormData();
  fd.append("file", file);

  return api.post(`/emails/upload/${encodeURIComponent(caseId)}`, fd).then((response) => response.data);
};
export const getCase=(id)=>api(`/cases/${id}`);
export const getCaseAnalyses=(id)=>api(`/analysis/case/${id}`);
export const getAnalysis=(id)=>api(`/analysis/${id}`);
export const getAdvanced=(id)=>api(`/advanced/analysis/${id}`);
export const advancedSearch=(q)=>api(`/advanced/search?q=${encodeURIComponent(q)}`);
export const advancedDashboard=()=>api('/advanced/dashboard');
export const intel=(type,value)=>type==='url'?api(`/intel/url?url=${encodeURIComponent(value)}`):api(`/intel/${type}/${encodeURIComponent(value)}`);
export const reportPdf = (id) => `${import.meta.env.VITE_API_BASE_URL}/reports/${id}/pdf`;
export const reportJson=(id)=>api(`/reports/${id}`);
export const gmailAuth=()=>api('/gmail/auth-url');
export const gmailStatus=()=>api('/gmail/status');
export const gmailSync=(max_emails=10)=>api.post('/gmail/sync',{},{params:{max_emails}}).then(r=>r.data);
export const gmailSyncStatus=(jobId)=>api.get(`/gmail/sync/${encodeURIComponent(jobId)}`).then(r=>r.data);
