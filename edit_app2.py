import re

with open('C:/Users/smecy/Downloads/WireSploit-v4.0.1-Patched/WireSploit-v4.0.1/web/app.js', 'r', encoding='utf-8') as f:
    content = f.read()

# Add renderScopes and deleteScope functions after filterTools
old_end = "}).join('')||'<div class=\"empty\">No matching resources.</div>';}else if(mode==='scopes'){renderScopes(q)}}async function repairTool"

new_end = (
    "}).join('')||'<div class=\"empty\">No matching resources.</div>';"
    "}else if(mode==='scopes'){renderScopes(q)}}"
    "function renderScopes(query){"
    "  const list=$('#toollist');"
    "  const scopes=window._scopes||[];"
    "  const filtered=scopes.filter(s=>(s.value+' '+(s.label||'')+' '+(s.type||'')).toLowerCase().includes(query));"
    "  if(!filtered.length){list.innerHTML='<div class=\"empty\">No matching scopes.</div>';return}"
    "  list.innerHTML=filtered.map(s=>{"
    "    const isDomain=s.type==='domain';"
    "    const hasSubdomainCoverage=isDomain;"
    "    const displayValue=isDomain && s.wildcard?`*.${s.value}`:s.value;"
    "    const subdomainBadge=hasSubdomainCoverage?'<span class=\"pill subdomain\">\\u{1F310} Subdomains covered</span>':'';"
    "    const typeLabel={'domain':'Domain','url':'URL','ip':'IP','cidr':'CIDR'}[s.type]||s.type;"
    "    return `<div class=\"tool\"><div class=\"toolmain\"><b>${esc(displayValue)}</b><small>${esc(typeLabel)} \\u{00B7} ${esc(s.label||'')}</small>${subdomainBadge}</div><div class=\"toolactions\"><button onclick=\"deleteScope('${esc(s.id)}')\">Delete</button></div></div>`}).join('');"
    "}"
    "async function deleteScope(id){"
    "  if(!confirm('Delete this authorized scope?'))return;"
    "  const msg=$('#toolmsg');"
    "  msg.innerHTML=`<div class=\"notice\">Deleting scope\\u{2026}</div>`;"
    "  try{await api(`/api/scopes/${encodeURIComponent(id)}`,{method:'DELETE'});msg.innerHTML=`<div class=\"notice\">Scope deleted.</div>`;window._scopes=await api('/api/scopes');filterTools()}catch(e){msg.innerHTML=`<div class=\"error\">${esc(e.message)}</div>`}}"
    "async function repairTool"
)

content = content.replace(old_end, new_end)

with open('C:/Users/smecy/Downloads/WireSploit-v4.0.1-Patched/WireSploit-v4.0.1/web/app.js', 'w', encoding='utf-8') as f:
    f.write(content)

print('Phase 2 done')