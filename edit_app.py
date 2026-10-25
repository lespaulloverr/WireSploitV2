import re

with open('C:/Users/smecy/Downloads/WireSploit-v4.0.1-Patched/WireSploit-v4.0.1/web/app.js', 'r', encoding='utf-8') as f:
    content = f.read()

# Find the filterTools function and add scopes tab handling
old_filter = "$('#tooltab-resources')?.classList.toggle('active',mode==='resources');if(mode==='integrations')"
new_filter = "$('#tooltab-resources')?.classList.toggle('active',mode==='resources');$('#tooltab-scopes')?.classList.toggle('active',mode==='scopes');if(mode==='integrations')"

content = content.replace(old_filter, new_filter)

# Also change the else to else if and add scopes branch
old_else = "}else{list.innerHTML=window._catalog.filter"
new_else = "}else if(mode==='resources'){list.innerHTML=window._catalog.filter"

content = content.replace(old_else, new_else)

# Add the scopes branch before the final closing
old_end = "}).join('')||'<div class=\"empty\">No matching resources.</div>';}}async function repairTool"
new_end = "}).join('')||'<div class=\"empty\">No matching resources.</div>';}else if(mode==='scopes'){renderScopes(q)}}async function repairTool"

content = content.replace(old_end, new_end)

with open('C:/Users/smecy/Downloads/WireSploit-v4.0.1-Patched/WireSploit-v4.0.1/web/app.js', 'w', encoding='utf-8') as f:
    f.write(content)

print('Phase 1 done')