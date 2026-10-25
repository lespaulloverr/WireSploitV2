with open('C:/Users/smecy/Downloads/WireSploit-v4.0.1-Patched/WireSploit-v4.0.1/web/app.js', 'r', encoding='utf-8') as f:
    content = f.read()

# Find the boundary
search = '}}\nasync function repairTool'
idx = content.find(search)
if idx >= 0:
    print('Found at:', idx)

    new_functions = (
        '}}\n'
        'function renderScopes(query){\n'
        '  const list=$(\'#toollist\');\n'
        '  const scopes=window._scopes||[];\n'
        '  const filtered=scopes.filter(s=>(s.value+\' \'+(s.label||\'\')+\' \'+(s.type||\'\')).toLowerCase().includes(query));\n'
        '  if(!filtered.length){list.innerHTML=\'<div class="empty">No matching scopes.</div>\';return}\n'
        '  list.innerHTML=filtered.map(s=>{\n'
        '    const isDomain=s.type===\'domain\';\n'
        '    const hasSubdomainCoverage=isDomain;\n'
        '    const displayValue=isDomain && s.wildcard?`*.${s.value}`:s.value;\n'
        '    const subdomainBadge=hasSubdomainCoverage?\'<span class="pill subdomain">\\u{1F310} Subdomains covered</span>\':\'\';\n'
        '    const typeLabel={\'domain\':\'Domain\',\'url\':\'URL\',\'ip\':\'IP\',\'cidr\':\'CIDR\'}[s.type]||s.type;\n'
        '    return `<div class="tool"><div class="toolmain"><b>${esc(displayValue)}</b><small>${esc(typeLabel)} \\u{00B7} ${esc(s.label||\'\')}</small>${subdomainBadge}</div><div class="toolactions"><button onclick="deleteScope(\'${esc(s.id)}\')">Delete</button></div></div>`}).join(\'\');\n'
        '}\n'
        'async function deleteScope(id){\n'
        '  if(!confirm(\'Delete this authorized scope?\'))return;\n'
        '  const msg=$(\'#toolmsg\');\n'
        '  msg.innerHTML=`<div class="notice">Deleting scope\\u{2026}</div>`;\n'
        '  try{await api(`/api/scopes/${encodeURIComponent(id)}`,{method:\'DELETE\'});msg.innerHTML=`<div class="notice">Scope deleted.</div>`;window._scopes=await api(\'/api/scopes\');filterTools()}catch(e){msg.innerHTML=`<div class="error">${esc(e.message)}</div>`}\n'
        '}\n'
        'async function repairTool'
    )

    content = content[:idx] + new_functions + content[idx + len('async function repairTool'):]

    with open('C:/Users/smecy/Downloads/WireSploit-v4.0.1-Patched/WireSploit-v4.0.1/web/app.js', 'w', encoding='utf-8') as f:
        f.write(content)

    print('Done!')
else:
    print('Boundary not found')