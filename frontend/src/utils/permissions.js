const viewer=['dashboard:view','case:view','investigation:view','risk:view','authentication:view','report:view','ioc:view','map:view'];
const analyst=[...viewer,'email:upload','analysis:run','case:create','case:edit','finding:create','notes:create','threatintel:view','report:download','ioc:lookup'];
const investigator=[...analyst,'evidence:view','relay:view','infrastructure:view','graph:view','campaign:view','gmail:investigate','audit:view'];
const admin=[...investigator,'users:manage','roles:manage','integrations:manage','api:manage','system:manage','audit:manage','case:delete','evidence:delete'];
export const ROLE_PERMISSIONS={VIEWER:viewer,ANALYST:analyst,INVESTIGATOR:investigator,ADMIN:admin};
export const can=(role,p)=>ROLE_PERMISSIONS[String(role||'VIEWER').toUpperCase()]?.includes(p)||false;
