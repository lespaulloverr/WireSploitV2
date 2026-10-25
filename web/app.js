const $=s=>document.querySelector(s);let state={view:'dashboard',iid:null,timer:null};
async function api(path,opt={}){let r=await fetch(path,{headers:{'Content-Type':'application/json',...(opt.headers||{})},...opt});let t=await r.text();let d;try{d=JSON.parse(t)}catch{d={detail:t}}if(!r.ok)throw Error(d.detail||`HTTP ${r.status}`);return d}
async function recordHistory(query, kind='search'){try{await api('/api/history',{method:'POST',body:JSON.stringify({query,kind})})}catch(e){console.warn('Failed to record history:',e)}}
const esc=x=>String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function shell(content,title='Dashboard'){document.body.innerHTML=`<div class="shell"><aside><div class="logo">WIRE<span>SPLOIT</span><small>PUBLIC-SOURCE INTELLIGENCE</small></div><nav>${[['dashboard','Overview'],['new','New Investigation'],['investigations','Investigations'],['tools','Tool Manager'],['evidence','Evidence'],['diagnostics','Diagnostics'],['settings','Settings']].map(x=>`<button class="${state.view===x[0]?'active':''}" onclick="go('${x[0]}')">${x[1]}</button>`).join('')}</nav><div class="sidefoot">LOCAL-FIRST · v4.0.0<br><span>Core engine does not depend on Ollama.</span></div></aside><main><header><div><div class="eyebrow">INVESTIGATION WORKSPACE</div><h1>${esc(title)}</h1></div><div class="statusdot"><i></i> Engine online</div></header><section>${content}</section></main></div>`}
async function go(v){state.view=v;try{if(v==='dashboard')return dashboard();if(v==='new')return newInv();if(v==='investigations')return invs();if(v==='tools')return tools();if(v==='evidence')return evidence();if(v==='diagnostics')return diagnostics();return settings()}catch(e){shell(`<div class="error"><b>Something went wrong</b><p>${esc(e.message)}</p></div>`,'Error')}}
async function dashboard(){let a=await api('/api/investigations');shell(`<div class="hero"><div><div class="eyebrow">READY</div><h2>Start an investigation without configuring a dozen separate tools.</h2><p>Enter what you know. WireSploit classifies it, selects compatible public-source providers, follows newly discovered identifiers and records provenance.</p><button class="primary big" onclick="go('new')">＋ New Investigation</button></div><div class="heroart"><b>${a.length}</b><span>saved investigations</span></div></div><div class="stats"><div><b>${a.length}</b><span>Investigations</span></div><div><b>1</b><span>Core engine</span></div><div><b>0</b><span>Required cloud AI</span></div><div><b>Local</b><span>Investigation data</span></div></div><div class="grid2"><div class="card"><div class="eyebrow">WORKFLOW</div><h3>One investigation, one workspace</h3><div class="steps"><div><b>01</b> Add known information</div><div><b>02</b> Run the research graph</div><div><b>03</b> Review findings and provenance</div><div><b>04</b> Review findings and evidence</div></div></div><div class="card"><div class="eyebrow">SAFETY</div><h3>Explicit authorization</h3><p>Passive public-source research is separate from higher-risk technical modules. SRM-authorized technical work is never silently enabled.</p></div></div>`}
function newInv(){shell(`<div class="card form"><div class="eyebrow">NEW CASE</div><h2>What are you investigating?</h2><input id="name" placeholder="Investigation name"><label>Known information</label><div id="inputs"><div class="inputrow"><select><option value="auto">Auto-detect</option><option>username</option><option>email</option><option>phone</option><option>domain</option><option>ip</option><option>search</option></select><input class="target" placeholder="Username, email, phone, domain, IP or other exact information"></div></div><button onclick="addInputRow()">＋ Add another</button><label class="permission"><input type="checkbox" id="srm"> <span><b>Permission for SRM tools given</b><small>Only enable this when you have the required authorization. Higher-risk technical modules remain limited and non-intrusive.</small></span></label><button class="primary big" onclick="createAndStart()">Start Investigation →</button><div id="msg"></div></div>`)}
function addInputRow(){$('#inputs').insertAdjacentHTML('beforeend',`<div class="inputrow"><select><option value="auto">Auto-detect</option><option>username</option><option>email</option><option>phone</option><option>domain</option><option>ip</option><option>search</option></select><input class="target" placeholder="Additional exact information"></div>`)}
async function createAndStart(){let msg=$('#msg');try{msg.innerHTML='<div class="notice">Creating investigation…</div>';let inv=await api('/api/investigations',{method:'POST',body:JSON.stringify({name:$('#name').value||'New Investigation',srm_authorized:$('#srm').checked})});let rows=[...document.querySelectorAll('.inputrow')];for(let r of rows){let v=r.querySelector('.target').value.trim();if(v){let k=r.querySelector('select').value;await api(`/api/investigations/${inv.id}/inputs`,{method:'POST',body:JSON.stringify({kind:k,value:v})});recordHistory(v,k)}}state.iid=inv.id;let run=await api(`/api/investigations/${inv.id}/start`,{method:'POST'});openInv(inv.id,run.id)}catch(e){msg.innerHTML=`<div class="error">${esc(e.message)}</div>`}}
async function invs(){let a=await api('/api/investigations');shell(`<div class="toolbar"><button class="primary" onclick="go('new')">＋ New Investigation</button></div><div class="list">${a.map(x=>`<button class="case" onclick="openInv('${x.id}')"><span><b>${esc(x.name)}</b><small>${esc(x.status)} · ${new Date(x.updated_at).toLocaleString()}</small></span><strong>→</strong></button>`).join('')||'<div class="empty">No investigations yet.</div>'}</div>`,'Investigations')}
async function openInv(iid,rid){state.iid=iid;state.view='investigation';let x=await api(`/api/investigations/${iid}`);let run=rid?await api(`/api/runs/${rid}`):(x.runs?.[0]?await api(`/api/runs/${x.runs[0].id}`):null);renderInv(x,run);if(run&&['queued','running'].includes(run.status))poll(run.id)}
function renderInv(x,r){shell(`<div class="casehead"><div><span class="pill">${esc(x.status)}</span><h2>${esc(x.name)}</h2><p>${x.inputs.map(i=>`<span class="tag">${esc(i.kind)}: ${esc(i.value)}</span>`).join(' ')}</p></div><div class="permanent-toggle"><label><input type="checkbox" ${x.permanent?'checked':''} onchange="togglePermanent(${x.id}, this.checked)"> Permanent investigation</label></div><button onclick="go('new')">＋ New</button></div><div class="export-toolbar"><button onclick="exportInv('json')">Export JSON</button><button onclick="exportInv('csv')">Export CSV</button><button onclick="exportInv('html')">Export HTML</button><button onclick="exportInv('pdf')">Export PDF</button></div><div id="runpanel">${runHtml(r)}</div><div class="tabs"><button onclick="invTab('findings')">Findings (${x.findings.length})</button><button onclick="invTab('activity')">Activity</button><button onclick="invTab('evidence')">Evidence (${x.evidence.length})</button><button onclick="invTab('notes')">Notes (${x.notes?.length||0})</button></div><div id="invtab">${findingsHtml(x.findings)}</div>`,'Investigation')}
function runHtml(r){if(!r)return '<div class="card empty">No run started.</div>';const pct=r.status==='complete'?100:(r.total_stages?Math.min(100,Math.round(((r.stage||0)/r.total_stages)*100)):0);const jobs=(r.jobs||[]).slice(-8).map(j=>'<div><span>'+esc(j.category)+' · '+esc(j.provider)+'</span><b class="'+(j.status==='complete'?'good':j.status==='error'?'bad':'muted')+'">'+esc(j.status)+'</b></div>').join('');return '<div class="card run"><div class="runhead"><div><div class="eyebrow">INVESTIGATION ENGINE</div><h3>'+esc((r.status||'').toUpperCase())+'</h3><p>'+esc(r.current||'Waiting…')+'</p></div><b>'+pct+'%</b></div><div class="'+(r.status==='error'?'bar error':'bar')+'"><i style="width:'+pct+'%"></i></div><div class="jobs">'+jobs+'</div></div>'}
function findingsHtml(fs){if(!fs.length)return '<div class="empty">No findings yet. Results will appear here as providers complete.</div>';const rows=fs.map(f=>'<tr><td><b>'+esc(f.value)+'</b><small>'+esc(f.url||'')+'</small></td><td>'+esc(f.category)+'</td><td>'+esc(f.provider)+'</td><td>'+Math.round(f.confidence*100)+'%</td></tr>').join('');return '<div class="card"><table><thead><tr><th>Finding</th><th>Category</th><th>Provider</th><th>Confidence</th></tr></thead><tbody>'+rows+'</tbody></table></div>'}
async function invTab(t){
  try{
    const x=await api('/api/investigations/'+state.iid);
    const r=x.runs&&x.runs[0]?await api('/api/runs/'+x.runs[0].id):null;
    const panel=$('#invtab');
    if(!panel)return;
    // Loading state
    panel.innerHTML='<div class="card"><div class="notice">Loading…</div></div>';
    if(t==='findings'){
      panel.innerHTML=findingsHtml(x.findings);
      return;
    }
    if(t==='activity'){
      panel.innerHTML='<div class="card timeline">'+(r?.events||[]).map(e=>'<div><b>'+esc(e.level)+'</b><span>'+esc(e.message)+'</span></div>').join('')+'</div>';
      return;
    }
    if(t==='evidence'){
      const isImage = (url) => {
        const imageExtensions = ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp'];
        return imageExtensions.some(ext => url.toLowerCase().endsWith(ext));
      };
      panel.innerHTML=`
        <div class="card">
          <div class="evidence-header">
            <h3>Evidence</h3>
            <button class="primary" onclick="openScreenshotModal()">📸 Capture Screenshot</button>
          </div>
          <div class="evidence-upload">
            <h4>Add Evidence</h4>
            <form id="evidence-form">
              <div>
                <label>Kind:</label>
                <select id="evidence-kind">
                  <option value="file">File</option>
                  <option value="finding">Finding</option>
                  <option value="note">Note</option>
                  <option value="other">Other</option>
                </select>
              </div>
              <div>
                <label>Title:</label>
                <input type="text" id="evidence-title" placeholder="Brief description">
              </div>
              <div>
                <label>Source:</label>
                <input type="text" id="evidence-source" placeholder="Where did this come from?">
              </div>
              <div>
                <label>Description:</label>
                <textarea id="evidence-description" placeholder="Details"></textarea>
              </div>
              <div>
                <label>File:</label>
                <input type="file" id="evidence-file">
              </div>
              <button type="submit" class="primary">Upload Evidence</button>
            </form>
          </div>
          <div class="evidence-list">
            ${x.evidence && x.evidence.length > 0 ? x.evidence.map(e=>`
              <div class="evidence-item">
                ${isImage(e.url) ? `<img src="/api/evidence/${e.id}/file" class="evidence-thumbnail" alt="Thumbnail">` : ''}
                <div class="evidence-content">
                  <b>${esc(e.title)}</b>
                  <div class="evidence-meta">
                    <span class="evidence-id">#${e.id}</span>
                    <span class="evidence-timestamp">${new Date(e.created_at).toLocaleString()}</span>
                  </div>
                  ${e.source ? `<div class="evidence-source">${esc(e.source)}</div>` : ''}
                  ${e.url && !isImage(e.url) ? `<div class="evidence-url">${esc(e.url)}</div>` : ''}
                  ${e.description ? `<div class="evidence-description">${esc(e.description)}</div>` : ''}
                </div>
              </div>
            `).join('') : '<div class="empty">No evidence yet.</div>'}
          </div>
        </div>

        <!-- Screenshot Capture Modal -->
        <div id="screenshot-modal" class="modal" style="display: none;">
          <div class="modal-content">
            <h4>Capture Screenshot</h4>
            <p class="muted">Enter a URL to capture. The target must be in an authorized scope.</p>
            <div id="screenshot-scope-warning" class="warning" style="display: none;"></div>
            <div>
              <label>URL:</label>
              <input type="url" id="screenshot-url" placeholder="https://example.com" required>
            </div>
            <div>
              <label>Title:</label>
              <input type="text" id="screenshot-title" placeholder="Screenshot title (optional)">
            </div>
            <div>
              <label>Description:</label>
              <textarea id="screenshot-description" placeholder="Description (optional)"></textarea>
            </div>
            <div class="modal-actions">
              <button class="primary" onclick="captureScreenshot()">Capture & Save</button>
              <button onclick="closeScreenshotModal()">Cancel</button>
            </div>
          </div>
        </div>
      `;
      return;
    }
    if(t==='notes'){
      panel.innerHTML=`
        <div class="card">
          <h3>Notes</h3>
          <div id="notes-list">
            ${x.notes && x.notes.length > 0 ? x.notes.map(n=>`
              <div class="note">
                <p>${esc(n.note)}</p>
                <div class="note-meta">
                  <span class="note-timestamp">${new Date(n.created_at).toLocaleString()}</span>
                </div>
                <div class="note-actions">
                  <button onclick="editNote('${n.id}')">Edit</button>
                  <button onclick="deleteNote('${n.id}')">Delete</button>
                </div>
              </div>
            `).join('') : '<div class="empty">No notes yet.</div>'}
          </div>
          <div class="note-form">
            <h4>Add Note</h4>
            <textarea id="note-input" placeholder="Write a note..." rows="3"></textarea>
            <div class="form-actions">
              <button id="add-note-btn" class="primary">Add Note</button>
              <span id="note-chars">0/1000</span>
            </div>
          </div>
        </div>
      `;
      // Update character count
      const noteInput = $('#note-input');
      const noteChars = $('#note-chars');
      if (noteInput && noteChars) {
        noteInput.addEventListener('input', () => {
          noteChars.textContent = \`\${noteInput.value.length}/1000\`;
        });
        // Initialize
        noteChars.textContent = \`0/1000\`;
      }
      return;
    }
  }catch(e){
    panel.innerHTML=\`<div class="error"><b>Something went wrong</b><p>${esc(e.message)}</p></div>\`;
  }
}
async function tools(){let [t,c,s]=await Promise.all([api('/api/tools'),api('/api/catalog'),api('/api/scopes')]);shell(`<div class="card"><div class="toolbar"><input id="q" placeholder="Search tools, categories or capabilities" oninput="filterTools()"></div><div class="tabs"><button id="tooltab-integrations" onclick="toolTab('integrations')">Integrated providers (${t.length})</button><button id="tooltab-resources" onclick="toolTab('resources')">Web resources (${c.length})</button><button id="tooltab-scopes" onclick="toolTab('scopes')">Authorized scopes (${s.length})</button></div><p class="muted">Integrated providers run inside WireSploit when available. Web resources open official external services and are not represented as locally installed tools.</p><div id="toollist"></div><div id="toolmsg"></div></div>`,'Tool Manager');window._tools=t;window._catalog=c;window._scopes=s;window._toolMode='integrations';filterTools()}
function toolTab(mode){window._toolMode=mode;filterTools()}
function filterTools(){let q=($('#q')?.value||'').toLowerCase(),list=$('#toollist');if(!list)return;const mode=window._toolMode||'integrations';$('#tooltab-integrations')?.classList.toggle('active',mode==='integrations');$('#tooltab-resources')?.classList.toggle('active',mode==='resources');$('#tooltab-scopes')?.classList.toggle('active',mode==='scopes');if(mode==='integrations'){list.innerHTML=window._tools.filter(t=>(t.name+' '+t.id+' '+(t.group||'')+' '+(t.categories||[]).join(' ')+' '+(t.notes||'')).toLowerCase().includes(q)).map(t=>{const d=t.diagnostic||{},repo=t.repo?`<a href="${esc(t.repo)}" target="_blank" rel="noopener noreferrer">Project</a>`:'';const install=d.repairable?`<button onclick="repairTool('${esc(t.id)}')">Install / Repair</button>`:'';let reason='';if(d.checks){const failed=d.checks.filter(x=>x.ok===false);if(failed.length>0){reason=failed.map(x=>x.detail).join('; ');}}return `<div class="tool"><div class="toolmain"><b>${esc(t.name)}</b><small>${esc(t.group||'')} · ${esc((t.categories||[]).join(', '))}</small>${t.notes?`<small>${esc(t.notes)}</small>`:''</div>${reason?`<small class="reason">${esc(reason)}</small>`:''}<div class="toolactions">${repo}${install}</div></div><span class="pill">${esc(d.status||'unknown')}</span></div>`}).join('')||'<div class="empty">No matching integrations.</div>';}else if(mode==='resources'){list.innerHTML=window._catalog.filter(t=>(t.name+' '+(t.category||'')+' '+(t.description||'')+' '+(t.group||'')).toLowerCase().includes(q)).map(t=>`<div class="tool"><div class="toolmain"><b>${esc(t.name)}</b><small>${esc(t.category||t.group||'OSINT resource')}</small><small>${esc(t.description||'Open-source or public web resource.')}</small><div class="toolactions"><a href="${esc(t.url)}" target="_blank" rel="noopener noreferrer">Open resource ↗</a></div></div><span class="pill">External</span></div>`).join('')||'<div class="empty">No matching resources.</div>';}}
function renderScopes(query){
  const list=$('#toollist');
  const scopes=window._scopes||[];
  const filtered=scopes.filter(s=>(s.value+' '+(s.label||'')+' '+(s.type||'')).toLowerCase().includes(query));
  if(!filtered.length){list.innerHTML='<div class="empty">No matching scopes.</div>';return}
  list.innerHTML=filtered.map(s=>{
    const isDomain=s.type==='domain';
    const hasSubdomainCoverage=isDomain;
    const displayValue=isDomain && s.wildcard?`*.${s.value}`:s.value;
    const subdomainBadge=hasSubdomainCoverage?'<span class="pill subdomain">\u{1F310} Subdomains covered</span>':'';
    const typeLabel={'domain':'Domain','url':'URL','ip':'IP','cidr':'CIDR'}[s.type]||s.type;
    return `<div class="tool"><div class="toolmain"><b>${esc(displayValue)}</b><small>${esc(typeLabel)} \u{00B7} ${esc(s.label||'')}</small>${subdomainBadge}</div><div class="toolactions"><button onclick="deleteScope('${esc(s.id)}')">Delete</button></div></div>`}).join('');
}
async function deleteScope(id){
  if(!confirm('Delete this authorized scope?'))return;
  const msg=$('#toolmsg');
  msg.innerHTML=`<div class="notice">Deleting scope\u{2026}</div>`;
  try{await api(`/api/scopes/${encodeURIComponent(id)}`,{method:'DELETE'});msg.innerHTML=`<div class="notice">Scope deleted.</div>`;window._scopes=await api('/api/scopes');filterTools()}catch(e){msg.innerHTML=`<div class="error">${esc(e.message)}</div>`}
}
async function repairTool(id){const t=window._tools.find(x=>x.id===id);if(!t)return;const hint=t.install_hint||'Install the provider and its dependencies.';if(!confirm(`Install or repair ${t.name}?\n\nThis runs WireSploit's predefined install workflow.\n${hint}`))return;const msg=$('#toolmsg');msg.innerHTML=`<div class="notice">Installing ${esc(t.name)}…</div>`;try{const result=await api(`/api/tools/${encodeURIComponent(id)}/repair`,{method:'POST'});msg.innerHTML=`<div class="notice">${esc(result.message||'Install workflow finished.')}: ${result.ok?'success':'needs attention'}</div>`;window._tools=await api('/api/tools');filterTools()}catch(e){msg.innerHTML=`<div class="error">${esc(e.message)}</div>`}}
async function evidence(){let a=await api('/api/investigations');shell(`<div class="card"><h3>Evidence register</h3><p class="muted">Only explicitly captured evidence appears here.</p>${a.map(x=>`<div class="tool"><b>${esc(x.name)}</b><button onclick="openInv('${x.id}')">Open</button></div>`).join('')||'<div class="empty">No evidence yet.</div>'}</div>`,'Evidence')}
async function diagnostics(){let d=await api('/api/diagnostics');shell(`<div class="stats"><div><b>${d.registered}</b><span>Registered</span></div><div><b>${d.ready}</b><span>Ready</span></div></div><div class="card"><pre>${esc(JSON.stringify(d,null,2))}</pre></div>`,'Diagnostics')}
async function settings(){
  shell(`<div class="card"><div class="tabs settings-tabs">
    <button class="active" onclick="settingsTab('resources')">Resources</button>
    <button onclick="settingsTab('privacy')">Privacy</button>
    <button onclick="settingsTab('history')">History</button>
  </div>
  <div id="settings-panel"></div></div>`,'Settings');
  settingsTab('resources');
}

async function settingsTab(tab){
  const panel=$('#settings-panel');
  if(!panel)return;
  if(tab==='resources'){
    panel.innerHTML=`<div class="grid2"><div class="card"><div class="eyebrow">RESOURCE POLICY</div><h3>Balanced</h3><p>Designed for the reported 8 GB Windows laptop. Provider concurrency is bounded and optional AI never blocks the evidence engine.</p></div></div>`;
  }else if(tab==='privacy'){
    panel.innerHTML=`<div class="card"><div class="eyebrow">PRIVACY</div><h3>Local-first</h3><p>Investigations persist locally. Evidence records are explicit and provider provenance is retained.</p></div>`;
  }else if(tab==='history'){
    panel.innerHTML=`<div class="card"><div class="eyebrow">SEARCH HISTORY</div>
      <div class="toolbar"><button class="primary" onclick="loadHistory()">Refresh</button>
      <button onclick="clearHistory()" style="margin-left:auto;">Clear All</button></div>
      <div id="history-list"></div></div>`;
    loadHistory();
  }
  // Update active tab
  document.querySelectorAll('.settings-tabs button').forEach(b=>{
    b.classList.toggle('active', b.textContent.toLowerCase().includes(tab));
  });
}

async function loadHistory(){
  const list=$('#history-list');
  if(!list)return;
  list.innerHTML='<div class="notice">Loading…</div>';
  try{
    const history=await api('/api/history');
    if(!history.length){
      list.innerHTML='<div class="empty">No search history yet.</div>';
      return;
    }
    list.innerHTML=history.map(h=>`
      <div class="history-item">
        <div class="history-main">
          <span class="history-kind">${esc(h.kind)}</span>
          <span class="history-query">${esc(h.query)}</span>
          <small class="history-time">${new Date(h.created_at).toLocaleString()}</small>
        </div>
        <button onclick="deleteHistory('${h.id}')" title="Delete">✕</button>
      </div>
    `).join('');
  }catch(e){
    list.innerHTML=`<div class="error">${esc(e.message)}</div>`;
  }
}

async function deleteHistory(hid){
  if(!confirm('Delete this history entry?'))return;
  try{
    await api(`/api/history/${hid}`,{method:'DELETE'});
    loadHistory();
  }catch(e){
    alert(`Failed to delete: ${e.message}`);
  }
}

async function clearHistory(){
  if(!confirm('Clear all search history? This cannot be undone.'))return;
  try{
    await api('/api/history',{method:'DELETE'});
    loadHistory();
  }catch(e){
    alert(`Failed to clear: ${e.message}`);
  }
}
// Note handling functions
async function addNote(){const noteInput=$('#note-input');const note=noteInput.value.trim();if(!note){alert('Note cannot be empty');return}try{const resp=await api(`/api/investigations/${state.iid}/notes`,{method:'POST',body:JSON.stringify({note})});noteInput.value='';await invTab('notes');// refresh the notes list}catch(e){alert(`Failed to add note: ${e.message}`)}}
async function editNote(id){const newNote=prompt('Edit note:');if(newNote===null||newNote.trim()==='')return;try{await api(`/api/investigations/notes/${id}`,{method:'PUT',body:JSON.stringify({note:newNote})});await invTab('notes');}catch(e){alert(`Failed to update note: ${e.message}`)}}
async function deleteNote(id){if(!confirm('Delete this note?'))return;try{await api(`/api/investigations/notes/${id}`,{method:'DELETE'});await invTab('notes');}catch(e){alert(`Failed to delete note: ${e.message}`)}}
// Permanent investigation toggle
async function togglePermanent(iid, permanent){try{await api(`/api/investigations/${iid}/permanent`,{method:'PUT',body:new URLSearchParams({permanent: permanent ? '1' : '0'})});}catch(e){alert(`Failed to update permanent status: ${e.message}`);}}
// Export investigation
async function exportInv(format) {
  try {
    const response = await fetch(`/api/investigations/${state.iid}/export/${format}`);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `investigation_${state.iid}.${format}`;
    a.click();
    window.URL.revokeObjectURL(url);
  } catch (e) {
    alert(`Failed to export: ${e.message}`);
  }
}

// Screenshot capture functions
function openScreenshotModal() {
  const modal = $('#screenshot-modal');
  if (modal) modal.style.display = 'flex';
  // Clear previous values
  const urlInput = $('#screenshot-url');
  const titleInput = $('#screenshot-title');
  const descInput = $('#screenshot-description');
  const warningDiv = $('#screenshot-scope-warning');
  if (urlInput) urlInput.value = '';
  if (titleInput) titleInput.value = '';
  if (descInput) descInput.value = '';
  if (warningDiv) {
    warningDiv.style.display = 'none';
    warningDiv.textContent = '';
  }
}

function closeScreenshotModal() {
  const modal = $('#screenshot-modal');
  if (modal) modal.style.display = 'none';
}

async function captureScreenshot() {
  const urlInput = $('#screenshot-url');
  const titleInput = $('#screenshot-title');
  const descInput = $('#screenshot-description');
  const warningDiv = $('#screenshot-scope-warning');
  const btn = document.querySelector('#screenshot-modal .primary');

  const url = urlInput?.value?.trim();
  if (!url) {
    alert('Please enter a URL');
    return;
  }

  // Validate URL format
  try {
    new URL(url);
  } catch {
    alert('Please enter a valid URL');
    return;
  }

  const title = titleInput?.value?.trim() || `Screenshot of ${url}`;
  const description = descInput?.value?.trim() || '';

  // Disable button during capture
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Capturing...';
  }
  if (warningDiv) {
    warningDiv.style.display = 'none';
    warningDiv.textContent = '';
  }

  try {
    // Call the screenshot endpoint
    const formData = new FormData();
    formData.append('url', url);
    const response = await fetch('/api/screenshot', {
      method: 'POST',
      body: formData
    });

    if (!response.ok) {
      const errorText = await response.text();
      if (response.status === 403) {
        // Check if we should show scope warning
        if (warningDiv) {
          warningDiv.textContent = 'This URL is not in an authorized scope. Please add it to scopes in the Security section first.';
          warningDiv.style.display = 'block';
        }
      }
      throw new Error(errorText || `HTTP ${response.status}`);
    }

    // Get the screenshot as blob
    const screenshotBlob = await response.blob();

    // Now upload as evidence
    const evidenceFormData = new FormData();
    evidenceFormData.append('file', screenshotBlob, 'screenshot.png');
    evidenceFormData.append('kind', 'screenshot');
    evidenceFormData.append('title', title);
    evidenceFormData.append('source', url);
    evidenceFormData.append('description', description);

    const uploadResponse = await fetch(`/api/investigations/${state.iid}/evidence/upload`, {
      method: 'POST',
      body: evidenceFormData
    });

    if (!uploadResponse.ok) {
      const err = await uploadResponse.text();
      throw new Error(err);
    }

    // Success - close modal and refresh evidence list
    closeScreenshotModal();
    await invTab('evidence');
    alert('Screenshot captured and saved as evidence!');
  } catch (err) {
    alert(`Failed to capture screenshot: ${err.message}`);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = 'Capture & Save';
    }
  }
}

// Evidence upload handling
document.addEventListener('submit',async e=>{if(e.target&&e.target.id==='evidence-form'){e.preventDefault();const form=e.target;const kind=form['evidence-kind'].value;const title=form['evidence-title'].value.trim();const source=form['evidence-source'].value.trim();const description=form['evidence-description'].value.trim();const fileInput=form['evidence-file'];const file=fileInput.files[0];if(!file){alert('Please select a file');return}const formData=new FormData();formData.append('file',file);formData.append('kind',kind);formData.append('title',title);formData.append('source',source);formData.append('description',description);try{const resp=await fetch(`/api/investigations/${state.iid}/evidence/upload`,{method:'POST',body:formData});if(!resp.ok){const err=await resp.text();throw new Error(err);}form.reset();await invTab('evidence');// refresh evidence list}catch(err){alert(`Failed to upload evidence: ${err.message}`);}}});
// Initialize note tab button handlers
document.addEventListener('click',async e=>{if(e.target&&e.target.id==='add-note-btn'){await addNote();}});
go('dashboard');