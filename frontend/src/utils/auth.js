export const DEMO_ACCOUNTS={
  ADMIN:{email:'admin@satguard.local',password:'admin123'},
  ANALYST:{email:'analyst@satguard.local',password:'analyst123'},
  INVESTIGATOR:{email:'investigator@satguard.local',password:'invest123'},
  VIEWER:{email:'viewer@satguard.local',password:'viewer123'}
};
export const getSession=()=>{try{return JSON.parse(localStorage.getItem('satguard_session')||'null')}catch{return null}};
export const saveSession=(s,remember=true)=>{const raw=JSON.stringify(s);if(remember)localStorage.setItem('satguard_session',raw);else sessionStorage.setItem('satguard_session',raw)};
export const clearSession=()=>{localStorage.removeItem('satguard_session');sessionStorage.removeItem('satguard_session');localStorage.removeItem('satguard_token');sessionStorage.removeItem('satguard_token')};
export const getToken=()=>localStorage.getItem('satguard_token')||sessionStorage.getItem('satguard_token');
export const roleOf=s=>String(s?.user?.role||s?.role||'VIEWER').toUpperCase();
