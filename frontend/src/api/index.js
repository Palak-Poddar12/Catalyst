import { api } from "./client";

export const getCases = () =>
  api.get("/cases");

export const createCase = (payload) =>
  api.post("/cases", payload);

export const uploadEmail = (caseId, file) => {
  const fd = new FormData();
  fd.append("file", file);

  return api.post(
    `/emails/upload/${encodeURIComponent(caseId)}`,
    fd
  );
};

export const getCase = (id) =>
  api.get(`/cases/${id}`);

export const getCaseAnalyses = (id) =>
  api.get(`/analysis/case/${id}`);

export const getAnalysis = (id) =>
  api.get(`/analysis/${id}`);

export const getAdvanced = (id) =>
  api.get(`/advanced/analysis/${id}`);

export const advancedSearch = (q) =>
  api.get(`/advanced/search?q=${encodeURIComponent(q)}`);

export const advancedDashboard = () =>
  api.get("/advanced/dashboard");

export const intel = (type, value) =>
  type === "url"
    ? api.get(`/intel/url?url=${encodeURIComponent(value)}`)
    : api.get(`/intel/${type}/${encodeURIComponent(value)}`);

export const reportPdf = (id) =>
  `${import.meta.env.VITE_API_BASE_URL}/reports/${id}/pdf`;

export const reportJson = (id) =>
  api.get(`/reports/${id}`);

export const gmailAuth = () =>
  api.get("/gmail/auth-url");

export const gmailStatus = () =>
  api.get("/gmail/status");

export const gmailSync = () =>
  api.post("/gmail/sync");
