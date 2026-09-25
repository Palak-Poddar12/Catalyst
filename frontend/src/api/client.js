import axios from 'axios';
import { getToken, clearSession } from '../utils/auth';

const base = import.meta.env.VITE_API_BASE_URL || '/api/v1';

export const api = axios.create({
  baseURL: base,
  timeout: 30000,
});

api.interceptors.request.use((config) => {
  const token = getToken();
  // Frontend-only prototype sessions must never be presented to FastAPI as real JWTs.
  if (token && !token.startsWith('satguard-local-')) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    // Do not destroy the frontend demo session because a backend data endpoint
    // happens to reject/require a different authentication scheme.
    const token = getToken();
    if (error.response?.status === 401 && token && !token.startsWith('satguard-local-')) {
      clearSession();
      window.location.assign('/login');
    }
    return Promise.reject(error);
  }
);
