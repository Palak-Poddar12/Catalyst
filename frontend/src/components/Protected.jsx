import {Navigate,useLocation} from 'react-router-dom';import {useAuth} from '../auth/AuthContext';
export default function Protected({children}){const {user}=useAuth();const loc=useLocation();return user?children:<Navigate to="/login" replace state={{from:loc.pathname}}/>}
