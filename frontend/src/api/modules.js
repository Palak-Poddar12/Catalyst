import {api} from './client';
export const authApi={login:(payload)=>api.post('/auth/login',payload),me:()=>api.get('/auth/me')};
export const dashboardApi={get:()=>api.get('/advanced/dashboard')};
export const casesApi={list:(params)=>api.get('/cases',{params}),get:(id)=>api.get(`/cases/${id}`),create:(data)=>api.post('/cases',data),delete:(id)=>api.delete(`/cases/${id}`)};
export const emailApi = {
  upload: (caseId, file) => {
    const f = new FormData();
    f.append("file", file);

    return api.post(
      `/emails/upload/${encodeURIComponent(caseId)}`,
      f
    );
  },
};
export const analysisApi={run:(id)=>api.post(`/analysis/${id}`),get:(id)=>api.get(`/analysis/${id}`)};
export const intelApi={ip:(ip)=>api.get(`/intel/ip/${encodeURIComponent(ip)}`),domain:(d)=>api.get(`/intel/domain/${encodeURIComponent(d)}`),url:(u)=>api.get('/intel/url',{params:{url:u}})};
export const advancedApi={analysis:(id)=>api.get(`/advanced/analysis/${id}`),search:(q)=>api.get('/advanced/search',{params:{q}})};
export const reportsApi={list:(params)=>api.get('/reports',{params}),generate:(data)=>api.post('/reports',data),download:(id)=>api.get(`/reports/${id}/download`,{responseType:'blob'})};
export const gmailApi={status:()=>api.get('/gmail/status'),messages:(params)=>api.get('/gmail/messages',{params}),triage:(data)=>api.post('/gmail/triage',data)};
export const adminApi={users:(params)=>api.get('/admin/users',{params}),audit:(params)=>api.get('/admin/audit-logs',{params}),roles:()=>api.get('/admin/roles'),settings:()=>api.get('/admin/settings')};
