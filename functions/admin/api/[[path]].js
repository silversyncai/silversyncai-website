// Cloudflare Pages Function: /admin/api/*
// Requires Cloudflare Access JWT, independently verified using Access public keys.
const reply = (data, status=200) => new Response(JSON.stringify(data), {status, headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});
const b64 = s => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')), c=>c.charCodeAt(0));
const decode = s => JSON.parse(new TextDecoder().decode(b64(s)));
async function authenticate(request,env){
  const team=(env.CF_ACCESS_TEAM_DOMAIN||'').replace(/^https?:\/\//,'').replace(/\/$/,'');
  const aud=env.CF_ACCESS_AUD;
  if(!team||!aud) throw new Error('Missing Access verification settings');
  const token=request.headers.get('Cf-Access-Jwt-Assertion');
  if(!token) return false;
  const parts=token.split('.'); if(parts.length!==3) return false;
  let header,payload; try {header=decode(parts[0]);payload=decode(parts[1]);}catch{return false;}
  if(header.alg!=='RS256'||!header.kid) return false;
  const now=Math.floor(Date.now()/1000);
  if(!Number.isFinite(payload.exp)||payload.exp<=now||!Number.isFinite(payload.iat)||payload.iat>now+60) return false;
  if(payload.iss!==`https://${team}` || !(Array.isArray(payload.aud)?payload.aud:[payload.aud]).includes(aud)) return false;
  const response=await fetch(`https://${team}/cdn-cgi/access/certs`);
  if(!response.ok) throw new Error('Unable to retrieve Access signing keys');
  const keys=(await response.json()).keys||[];
  const jwk=keys.find(k=>k.kid===header.kid&&k.kty==='RSA'); if(!jwk) return false;
  const key=await crypto.subtle.importKey('jwk',jwk,{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
  const bytes=new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  return crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,b64(parts[2]),bytes);
}
const allowed=['New','Contacted','Qualified','Proposal Sent','Won','Lost'];
export async function onRequest({request,env,params}){
  if(!env.DB)return reply({error:'Database binding DB is missing'},503);
  let valid=false;
  try{valid=await authenticate(request,env);}catch(e){console.error('Access verification failed',e);return reply({error:'Authentication configuration unavailable'},503);}
  if(!valid)return reply({error:'Unauthorized'},401);
  const url=new URL(request.url), method=request.method;
  const route=(Array.isArray(params.path)?params.path.join('/'):params.path||'').replace(/\/$/,'');
  try{
    if(route==='leads'&&method==='GET'){
      const status=url.searchParams.get('status')||'';
      if(status&&!allowed.includes(status))return reply({error:'Invalid status'},400);
      const q=(url.searchParams.get('q')||'').trim().slice(0,100);
      const page=Math.max(1,Math.min(10000,Number.parseInt(url.searchParams.get('page')||'1',10)||1));
      const size=25,offset=(page-1)*size;
      let where=' WHERE 1=1',bindings=[];
      if(status){where+=' AND status = ?';bindings.push(status);}
      if(q){where+=' AND (business_name LIKE ? OR contact_name LIKE ? OR phone LIKE ? OR email LIKE ?)';const v=`%${q.replace(/[\\%_]/g,'\\$&')}%`;where=where.replaceAll(' LIKE ?'," LIKE ? ESCAPE '\\'");bindings.push(v,v,v,v);}
      const count=await env.DB.prepare(`SELECT COUNT(*) AS total FROM leads${where}`).bind(...bindings).first();
      const rows=await env.DB.prepare(`SELECT id,business_name,contact_name,phone,email,service,message,status,created_at FROM leads${where} ORDER BY id DESC LIMIT ? OFFSET ?`).bind(...bindings,size,offset).all();
      const stats=await env.DB.prepare('SELECT status, COUNT(*) AS count FROM leads GROUP BY status').all();
      return reply({leads:rows.results||[],total:count?.total||0,page,pageSize:size,stats:stats.results||[]});
    }
    const match=/^leads\/(\d+)$/.exec(route);
    if(match&&method==='PATCH'){
      const origin=request.headers.get('Origin');
      if(origin&&new URL(origin).origin!==url.origin)return reply({error:'Invalid origin'},403);
      if(!(request.headers.get('content-type')||'').includes('application/json'))return reply({error:'Expected JSON'},415);
      if(Number(request.headers.get('content-length')||0)>2048)return reply({error:'Request too large'},413);
      let body;try{body=await request.json();}catch{return reply({error:'Invalid JSON'},400);}
      if(!allowed.includes(body?.status))return reply({error:'Invalid status'},400);
      const result=await env.DB.prepare('UPDATE leads SET status=? WHERE id=?').bind(body.status,Number(match[1])).run();
      if(!result.meta?.changes)return reply({error:'Lead not found'},404);
      return reply({ok:true});
    }
    return reply({error:'Not found'},404);
  }catch(e){console.error('CRM query error',e);return reply({error:'Unable to process request'},500);}
}
