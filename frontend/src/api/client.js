const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000/api/v1';
export async function api(path, options={}) {
  const res = await fetch(`${API_BASE}${path}`, { ...options, headers:{ ...(options.body instanceof FormData ? {} : {'Content-Type':'application/json'}), ...(options.headers||{}) }});
  const text = await res.text(); let data={}; try{data=text?JSON.parse(text):{}}catch{data={detail:text};}
  if(!res.ok) throw new Error(data.detail || `Request failed (${res.status})`);
  return data;
}
export const apiBase=API_BASE;
