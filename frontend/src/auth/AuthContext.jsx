import {createContext,useContext,useState} from 'react';
import {getSession,login,logout} from './demoAuth';
const C=createContext(null);
export function AuthProvider({children}){const [user,setUser]=useState(getSession());const signIn=(u,p,r)=>{const x=login(u,p,r);if(x)setUser(x);return x};const signOut=()=>{logout();setUser(null)};return <C.Provider value={{user,signIn,signOut}}>{children}</C.Provider>}
export const useAuth=()=>useContext(C);
