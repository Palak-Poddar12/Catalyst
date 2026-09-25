import axios from 'axios';
import {getToken,clearSession} from '../utils/auth';
const base=import.meta.env.VITE_API_BASE_URL||'/api/v1';
export const api=axios.create({baseURL:base,timeout:30000});
api.interceptors.request.use(c=>{const t=getToken();if(t)c.headers.Authorization=`Bearer ${t}`;return c});
api.interceptors.response.use(r=>r,e=>{if(e.response?.status===401){clearSession();window.location.assign('/login')}return Promise.reject(e)});
