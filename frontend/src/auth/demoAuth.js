const KEY='satguard_demo_session';
export const DEMO_USERS=[
 {username:'admin',password:'admin123',name:'SOC Administrator',role:'National Cyber Admin'},
 {username:'analyst',password:'analyst123',name:'Forensic Analyst',role:'Forensic Analyst'},
 {username:'investigator',password:'invest123',name:'Investigation Officer',role:'Investigator'},
 {username:'viewer',password:'viewer123',name:'Read-only Viewer',role:'Viewer'}
];
export function login(username,password,remember=true){const u=DEMO_USERS.find(x=>x.username===username&&x.password===password);if(!u)return null;const s={username:u.username,name:u.name,role:u.role,loggedAt:new Date().toISOString()};(remember?localStorage:sessionStorage).setItem(KEY,JSON.stringify(s));return s;}
export function logout(){localStorage.removeItem(KEY);sessionStorage.removeItem(KEY);}
export function getSession(){try{return JSON.parse(localStorage.getItem(KEY)||sessionStorage.getItem(KEY)||'null')}catch{return null}}
