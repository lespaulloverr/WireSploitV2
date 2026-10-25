import asyncio
import json
import csv
import io
import html
from fastapi import FastAPI, HTTPException, Request, Depends, UploadFile, File, Form
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import platform, sys, os, re

from playwright.async_api import async_playwright
import subprocess

from config import get_config, get_secret
config = get_config()

ROOT = Path(__file__).resolve().parent

def _load_local_env(path: Path):
    """Load simple KEY=VALUE settings from the ignored local .env without a new dependency."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding='utf-8-sig', errors='replace').splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('export '):
            line = line[7:].lstrip()
        if '=' not in line:
            continue
        key, value = line.split('=', 1)
        key = key.strip()
        value = value.strip()
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', key):
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('\"', "'"):
            value = value[1:-1]
        # Explicit environment variables take precedence over local file settings.
        os.environ.setdefault(key, value)

_load_local_env(ROOT / '.env')

from engine import store, engine, tooling, security
from engine.catalog import WEB_TOOLS
from engine.awesome_catalog import as_catalog as awesome_catalog
WEB = ROOT / 'web'
store.init()

app = FastAPI(title='WireSploit', version='4.0.0')
app.mount('/static', StaticFiles(directory=WEB), name='static')

# Track cleanup task for graceful shutdown
cleanup_task = None


@app.on_event("startup")
async def startup_event():
    global cleanup_task
    # Install Playwright browsers if not present
    def install_browsers():
        try:
            subprocess.run([sys.executable, "-m", "playwright", "install", "firefox"], check=True, capture_output=True)
            print("Playwright Firefox browser installed.")
        except Exception as e:
            print(f"Failed to install Playwright browsers: {e}")
    # Run in a thread to avoid blocking the event loop
    await asyncio.to_thread(install_browsers)

    async def cleanup_loop():
        while True:
            await asyncio.sleep(24 * 60 * 60)  # 24 hours
            deleted = store.delete_old_investigations(days=3)
            if deleted:
                print(f"Cleaned up {deleted} old investigations")
            # Clean up old search history
            deleted_history = store.cleanup_search_history(days=3)
            if deleted_history:
                print(f"Cleaned up {deleted_history} old search history entries")
            # Clean up orphaned evidence files
            deleted_orphans = store.cleanup_orphaned_evidence_files()
            if deleted_orphans:
                print(f"Cleaned up {deleted_orphans} orphaned evidence files")
    cleanup_task = asyncio.create_task(cleanup_loop())


@app.on_event("shutdown")
async def shutdown_event():
    global cleanup_task
    if cleanup_task:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass
    print("Cleanup task stopped gracefully")


class Inv(BaseModel):
    name: str = 'New Investigation'
    srm_authorized: bool = False

class Input(BaseModel):
    kind: str = 'auto'
    value: str

class Evidence(BaseModel):
    kind: str = 'finding'
    title: str
    source: str = ''
    url: str = ''
    description: str = ''

class Scope(BaseModel):
    value: str
    label: str = ''

# Validation functions imported from validation module
from validation import (
    validate_username,
    validate_email,
    validate_phone,
    validate_domain,
    validate_url,
    validate_ip,
    classify_and_validate,
)

ALLOWED_ORIGINS = {
    f"http://{config['HOST']}:{config['PORT']}",
    f"http://localhost:{config['PORT']}",
}

def require_same_origin(request: Request):
    origin = request.headers.get('origin')
    referer = request.headers.get('referer')
    if origin is not None and origin not in ALLOWED_ORIGINS:
        raise HTTPException(403, 'Cross-origin request rejected')
    if origin is None and referer is not None and not any(
        referer.startswith(o + '/') or referer == o for o in ALLOWED_ORIGINS
    ):
        raise HTTPException(403, 'Cross-origin request rejected')
    return True

ALLOWED_KINDS = {'auto', 'username', 'email', 'phone', 'domain', 'ip', 'search'}

@app.get('/')
def home():
    return FileResponse(WEB / 'index.html')

@app.get('/api/health')
def health():
    return {
        'ok': True,
        'version': '4.0.0',
        'python': sys.version.split()[0],
        'platform': platform.platform(),
        'providers': len(tooling.SPECS),
    }

@app.get('/api/investigations')
def investigations(_: bool = Depends(require_same_origin)):
    return store.list_investigations()

@app.post('/api/investigations')
def create(x: Inv, _: bool = Depends(require_same_origin)):
    # Validate investigation name
    name = x.name.strip()
    if not name:
        raise HTTPException(400, 'Investigation name cannot be empty')
    if len(name) > 200:
        raise HTTPException(400, 'Investigation name too long (max 200 characters)')
    return store.create_investigation(name, x.srm_authorized)

@app.get('/api/investigations/{iid}')
def get(iid: str, _: bool = Depends(require_same_origin)):
    x = store.get_investigation(iid)
    if not x:
        raise HTTPException(404, 'Investigation not found')
    runs = store.rows(
        'SELECT * FROM runs WHERE investigation_id=? ORDER BY started_at DESC', (iid,)
    )
    x['runs'] = [dict(r) for r in runs]
    x['findings'] = store.findings_for(iid)
    x['evidence'] = store.evidence_for(iid)
    return x

@app.post('/api/investigations/{iid}/inputs')
def add_input(iid: str, x: Input, _: bool = Depends(require_same_origin)):
    if not store.get_investigation(iid):
        raise HTTPException(404, 'Investigation not found')
    value = x.value.strip()
    if not value:
        raise HTTPException(400, 'Input value cannot be empty')
    kind = x.kind
    if kind == 'auto':
        # Classify and validate
        input_type, is_valid, normalized, error_msg = classify_and_validate(value)
        if not is_valid:
            raise HTTPException(400, error_msg or 'Invalid input')
        # Use the classified kind for storage
        final_kind = input_type
        # Store the normalized value (lowercased for email/username, etc.)
        final_value = normalized
    else:
        if kind not in ALLOWED_KINDS:
            raise HTTPException(400, f'Invalid input kind: {kind}')
        # Validate based on the given kind
        if kind == 'username':
            is_valid, normalized, error_msg = validate_username(value)
        elif kind == 'email':
            is_valid, normalized, error_msg = validate_email(value)
        elif kind == 'phone':
            is_valid, normalized, error_msg = validate_phone(value)
        elif kind == 'domain':
            is_valid, normalized, error_msg = validate_domain(value)
        elif kind == 'url':
            is_valid, normalized, error_msg = validate_url(value)
        elif kind == 'ip':
            is_valid, normalized, error_msg = validate_ip(value)
        else:  # 'search' or any other
            is_valid, normalized, error_msg = True, value.lower(), None
        if not is_valid:
            raise HTTPException(400, error_msg or 'Invalid input')
        final_kind = kind
        final_value = normalized
    return {'id': store.add_input(iid, final_kind, final_value)}

@app.post('/api/investigations/{iid}/start')
async def start(iid: str, _: bool = Depends(require_same_origin)):
    inv = store.get_investigation(iid)
    if not inv:
        raise HTTPException(404, 'Investigation not found')
    if not inv['inputs']:
        raise HTTPException(400, 'Add at least one target before starting.')
    active = store.row(
        "SELECT id FROM runs WHERE investigation_id=? AND status IN ('queued','running') ORDER BY started_at DESC",
        (iid,),
    )
    if active:
        return store.get_run(active['id'])
    rid = store.create_run(iid, 8)
    engine.launch(rid, iid)
    return store.get_run(rid)

@app.get('/api/runs/{rid}')
def run(rid: str, _: bool = Depends(require_same_origin)):
    x = store.get_run(rid)
    if not x:
        raise HTTPException(404, 'Run not found')
    return x

@app.post('/api/investigations/{iid}/evidence')
def evidence(iid: str, x: Evidence, _: bool = Depends(require_same_origin)):
    if not store.get_investigation(iid):
        raise HTTPException(404, 'Investigation not found')
    # Validate url field for metadata-only evidence to prevent path traversal
    if x.url:
        # Reject paths with directory traversal sequences
        if '..' in x.url or '/' in x.url or '\\' in x.url:
            raise HTTPException(400, 'Invalid url field: path traversal not allowed')
    return {'id': store.add_evidence(iid, x.kind, x.title, x.source, x.url, x.description)}

@app.get('/api/tools')
def tools():
    return tooling.list_tools()

@app.get('/api/investigations/{iid}/export/json')
def export_json(iid: str, _: bool = Depends(require_same_origin)):
    # Get investigation data with runs, findings, evidence
    x = store.get_investigation(iid)
    if not x:
        raise HTTPException(404, 'Investigation not found')
    runs = store.rows(
        'SELECT * FROM runs WHERE investigation_id=? ORDER BY started_at DESC', (iid,)
    )
    x['runs'] = [dict(r) for r in runs]
    x['findings'] = store.findings_for(iid)
    x['evidence'] = store.evidence_for(iid)
    x['notes'] = store.get_investigation_notes(iid)
    # Convert to JSON string
    json_str = json.dumps(x, indent=2)
    # Return as downloadable file
    return StreamingResponse(
        io.StringIO(json_str),
        media_type='application/json',
        headers={'Content-Disposition': f'attachment; filename=investigation_{iid}.json'}
    )

def _csv_sanitize(value):
    """Sanitize CSV cell to prevent formula injection.
    Prefix cells starting with =, +, -, @ with a tab character (OWASP recommendation)."""
    if value is None:
        return ''
    s = str(value)
    if s and s[0] in ('=', '+', '-', '@'):
        return '\t' + s
    return s


@app.get('/api/investigations/{iid}/export/csv')
def export_csv(iid: str, _: bool = Depends(require_same_origin)):
    if not store.get_investigation(iid):
        raise HTTPException(404, 'Investigation not found')
    findings = store.findings_for(iid)
    notes = store.get_investigation_notes(iid)
    # Prepare rows for CSV
    rows = []
    # Common columns
    common_cols = ['id', 'investigation_id', 'created_at', 'type']
    # Finding-specific columns
    finding_cols = ['category', 'provider', 'entity_key', 'value', 'url', 'confidence', 'exact_match', 'evidence_json']
    # Note-specific columns
    note_cols = ['note']
    # All columns
    fieldnames = common_cols + finding_cols + note_cols
    # Add findings
    for f in findings:
        row = {
            'id': _csv_sanitize(f.get('id')),
            'investigation_id': _csv_sanitize(f.get('investigation_id')),
            'created_at': _csv_sanitize(f.get('created_at')),
            'type': _csv_sanitize('finding'),
        }
        for col in finding_cols:
            row[col] = _csv_sanitize(f.get(col, ''))
        for col in note_cols:
            row[col] = _csv_sanitize('')
        rows.append(row)
    # Add notes
    for note in notes:
        row = {
            'id': _csv_sanitize(note.get('id')),
            'investigation_id': _csv_sanitize(note.get('investigation_id')),
            'created_at': _csv_sanitize(note.get('created_at')),
            'type': _csv_sanitize('note'),
        }
        for col in finding_cols:
            row[col] = _csv_sanitize('')
        for col in note_cols:
            row[col] = _csv_sanitize(note.get(col, ''))
        rows.append(row)
    # Write CSV
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    output.seek(0)
    return StreamingResponse(
        output,
        media_type='text/csv',
        headers={'Content-Disposition': f'attachment; filename=investigation_{iid}.csv'}
    )

def _h(value):
    """HTML escape helper that handles None and non-string values."""
    if value is None:
        return ''
    return html.escape(str(value))


@app.get('/api/investigations/{iid}/export/html')
def export_html(iid: str, _: bool = Depends(require_same_origin)):
    x = store.get_investigation(iid)
    if not x:
        raise HTTPException(404, 'Investigation not found')
    runs = store.rows(
        'SELECT * FROM runs WHERE investigation_id=? ORDER BY started_at DESC', (iid,)
    )
    x['runs'] = [dict(r) for r in runs]
    x['findings'] = store.findings_for(iid)
    x['evidence'] = store.evidence_for(iid)
    x['notes'] = store.get_investigation_notes(iid)
    # Generate HTML with proper escaping
    html_content = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Investigation {_h(x.get('name', 'Untitled'))}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            h1 {{ color: #2c3e50; }}
            h2 {{ color: #3498db; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            tr:nth-child(even) {{ background-color: #f9f9f9; }}
        </style>
    </head>
    <body>
        <h1>Investigation Report</h1>
        <p><strong>ID:</strong> {_h(x.get('id'))}</p>
        <p><strong>Name:</strong> {_h(x.get('name'))}</p>
        <p><strong>Status:</strong> {_h(x.get('status'))}</p>
        <p><strong>Created:</strong> {_h(x.get('created_at'))}</p>
        <p><strong>Updated:</strong> {_h(x.get('updated_at'))}</p>
        <p><strong>SRM Authorized:</strong> {_h(x.get('srm_authorized'))}</p>

        <h2>Inputs</h2>
        <table>
            <tr>
                <th>ID</th>
                <th>Investigation ID</th>
                <th>Kind</th>
                <th>Value</th>
                <th>Normalized</th>
                <th>Source</th>
                <th>Created At</th>
            </tr>
        '''
    for inp in x.get('inputs', []):
        html_content += f'''
            <tr>
                <td>{_h(inp.get('id'))}</td>
                <td>{_h(inp.get('investigation_id'))}</td>
                <td>{_h(inp.get('kind'))}</td>
                <td>{_h(inp.get('value'))}</td>
                <td>{_h(inp.get('normalized'))}</td>
                <td>{_h(inp.get('source'))}</td>
                <td>{_h(inp.get('created_at'))}</td>
            </tr>
        '''
    html_content += '''
        </table>
        <h2>Runs</h2>
        <table>
            <tr>
                <th>ID</th>
                <th>Investigation ID</th>
                <th>Status</th>
                <th>Stage</th>
                <th>Total Stages</th>
                <th>Current</th>
                <th>Started At</th>
                <th>Finished At</th>
                <th>Error</th>
            </tr>
        '''
    for run in x.get('runs', []):
        html_content += f'''
            <tr>
                <td>{_h(run.get('id'))}</td>
                <td>{_h(run.get('investigation_id'))}</td>
                <td>{_h(run.get('status'))}</td>
                <td>{_h(run.get('stage'))}</td>
                <td>{_h(run.get('total_stages'))}</td>
                <td>{_h(run.get('current'))}</td>
                <td>{_h(run.get('started_at'))}</td>
                <td>{_h(run.get('finished_at'))}</td>
                <td>{_h(run.get('error'))}</td>
            </tr>
        '''
    html_content += '''
        </table>
        <h2>Findings</h2>
        <table>
            <tr>
                <th>ID</th>
                <th>Run ID</th>
                <th>Category</th>
                <th>Provider</th>
                <th>Entity Key</th>
                <th>Value</th>
                <th>URL</th>
                <th>Confidence</th>
                <th>Exact Match</th>
                <th>Evidence JSON</th>
                <th>Created At</th>
            </tr>
        '''
    for find in x.get('findings', []):
        html_content += f'''
            <tr>
                <td>{_h(find.get('id'))}</td>
                <td>{_h(find.get('run_id'))}</td>
                <td>{_h(find.get('category'))}</td>
                <td>{_h(find.get('provider'))}</td>
                <td>{_h(find.get('entity_key'))}</td>
                <td>{_h(find.get('value'))}</td>
                <td>{_h(find.get('url'))}</td>
                <td>{_h(find.get('confidence'))}</td>
                <td>{_h(find.get('exact_match'))}</td>
                <td>{_h(find.get('evidence_json'))}</td>
                <td>{_h(find.get('created_at'))}</td>
            </tr>
        '''
    html_content += '''
        </table>
        <h2>Evidence</h2>
        <table>
            <tr>
                <th>ID</th>
                <th>Investigation ID</th>
                <th>Kind</th>
                <th>Title</th>
                <th>Source</th>
                <th>URL</th>
                <th>Description</th>
                <th>SHA256</th>
                <th>Created At</th>
            </tr>
        '''
    for ev in x.get('evidence', []):
        html_content += f'''
            <tr>
                <td>{_h(ev.get('id'))}</td>
                <td>{_h(ev.get('investigation_id'))}</td>
                <td>{_h(ev.get('kind'))}</td>
                <td>{_h(ev.get('title'))}</td>
                <td>{_h(ev.get('source'))}</td>
                <td>{_h(ev.get('description'))}</td>
                <td>{_h(ev.get('sha256'))}</td>
                <td>{_h(ev.get('created_at'))}</td>
            </tr>
        '''
    html_content += '''
    </table>
    <h2>Notes</h2>
    <table>
        <tr>
            <th>ID</th>
            <th>Investigation ID</th>
            <th>Note</th>
            <th>Created At</th>
        </tr>
    '''
    for note in x.get('notes', []):
        html_content += f'''
        <tr>
            <td>{_h(note.get('id'))}</td>
            <td>{_h(note.get('investigation_id'))}</td>
            <td>{_h(note.get('note'))}</td>
            <td>{_h(note.get('created_at'))}</td>
        </tr>
    '''
    html_content += '''
    </table>
</body>
</html>
'''
    return StreamingResponse(
        io.StringIO(html_content),
        media_type='text/html',
        headers={'Content-Disposition': f'attachment; filename=investigation_{iid}.html'}
    )

@app.get('/api/investigations/{iid}/export/pdf')
def export_pdf(iid: str, _: bool = Depends(require_same_origin)):
    if not store.get_investigation(iid):
        raise HTTPException(404, 'Investigation not found')
    # Get data
    x = store.get_investigation(iid)
    runs = store.rows(
        'SELECT * FROM runs WHERE investigation_id=? ORDER BY started_at DESC', (iid,)
    )
    x['runs'] = [dict(r) for r in runs]
    x['findings'] = store.findings_for(iid)
    x['evidence'] = store.evidence_for(iid)
    # Create PDF buffer
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    # Simple layout: we'll write text
    p.setFont("Helvetica-Bold", 16)
    p.drawString(50, height - 50, f"Investigation Report")
    p.setFont("Helvetica", 12)
    p.drawString(50, height - 80, f"ID: {x.get('id')}")
    p.drawString(50, height - 100, f"Name: {x.get('name')}")
    p.drawString(50, height - 120, f"Status: {x.get('status')}")
    p.drawString(50, height - 140, f"Created: {x.get('created_at')}")
    p.drawString(50, height - 160, f"Updated: {x.get('updated_at')}")
    p.drawString(50, height - 180, f"SRM Authorized: {x.get('srm_authorized')}")
    y = height - 220
    p.setFont("Helvetica-Bold", 14)
    p.drawString(50, y, "Inputs")
    y -= 20
    p.setFont("Helvetica", 10)
    for inp in x.get('inputs', []):
        text = f"ID: {inp.get('id')}, Kind: {inp.get('kind')}, Value: {inp.get('value')}"
        p.drawString(50, y, text)
        y -= 15
        if y < 50:
            p.showPage()
            y = height - 50
    y -= 10
    p.setFont("Helvetica-Bold", 14)
    p.drawString(50, y, "Runs")
    y -= 20
    p.setFont("Helvetica", 10)
    for run in x.get('runs', []):
        text = f"ID: {run.get('id')}, Status: {run.get('status')}, Stage: {run.get('stage')}"
        p.drawString(50, y, text)
        y -= 15
        if y < 50:
            p.showPage()
            y = height - 50
    y -= 10
    p.setFont("Helvetica-Bold", 14)
    p.drawString(50, y, "Findings")
    y -= 20
    p.setFont("Helvetica", 10)
    for find in x.get('findings', []):
        text = f"ID: {find.get('id')}, Category: {find.get('category')}, Value: {find.get('value')}"
        p.drawString(50, y, text)
        y -= 15
        if y < 50:
            p.showPage()
            y = height - 50
    y -= 10
    p.setFont("Helvetica-Bold", 14)
    p.drawString(50, y, "Evidence")
    y -= 20
    p.setFont("Helvetica", 10)
    for ev in x.get('evidence', []):
        text = f"ID: {ev.get('id')}, Kind: {ev.get('kind')}, Title: {ev.get('title')}"
        p.drawString(50, y, text)
        y -= 15
        if y < 50:
            p.showPage()
            y = height - 50
    y -= 10
    p.setFont("Helvetica-Bold", 14)
    p.drawString(50, y, "Notes")
    y -= 20
    p.setFont("Helvetica", 10)
    for note in x.get('notes', []):
        text = f"ID: {note.get('id')}, Note: {note.get('note')}"
        p.drawString(50, y, text)
        y -= 15
        if y < 50:
            p.showPage()
            y = height - 50
    p.showPage()
    p.save()
    buffer.seek(0)
    return StreamingResponse(
        buffer,
        media_type='application/pdf',
        headers={'Content-Disposition': f'attachment; filename=investigation_{iid}.pdf'}
    )

@app.get('/api/investigations/{iid}/graph')
def get_investigation_graph(iid: str, _: bool = Depends(require_same_origin)):
    x = store.get_investigation(iid)
    if not x:
        raise HTTPException(404, 'Investigation not found')
    runs = store.rows(
        'SELECT * FROM runs WHERE investigation_id=? ORDER BY started_at DESC', (iid,)
    )
    x['runs'] = [dict(r) for r in runs]
    x['findings'] = store.findings_for(iid)
    x['evidence'] = store.evidence_for(iid)
    # Build graph data
    nodes = []
    edges = []
    # Add investigation node
    nodes.append({'id': f'inv_{iid}', 'label': x.get('name', 'Investigation'), 'type': 'investigation'})
    # Add input nodes and edges to investigation
    for inp in x.get('inputs', []):
        inp_id = f'inp_{inp["id"]}'
        nodes.append({'id': inp_id, 'label': f"{inp.get('kind')}: {inp.get('value')}", 'type': 'input'})
        edges.append({'from': inp_id, 'to': f'inv_{iid}'})
    # Add run nodes and edges to investigation
    for run in x.get('runs', []):
        run_id = f'run_{run["id"]}'
        nodes.append({'id': run_id, 'label': f"Run {run.get('status')}", 'type': 'run'})
        edges.append({'from': run_id, 'to': f'inv_{iid}'})
    # Add finding nodes and edges to run
    for find in x.get('findings', []):
        find_id = f'find_{find["id"]}'
        nodes.append({'id': find_id, 'label': f"{find.get('category')}: {find.get('value')}", 'type': 'finding'})
        edges.append({'from': find_id, 'to': f"run_{find.get('run_id')}"})
    # Add evidence nodes and edges to investigation
    for ev in x.get('evidence', []):
        ev_id = f'ev_{ev["id"]}'
        nodes.append({'id': ev_id, 'label': f"{ev.get('kind')}: {ev.get('title')}", 'type': 'evidence'})
        edges.append({'from': ev_id, 'to': f'inv_{iid}'})
    # Return JSON
    return {'nodes': nodes, 'edges': edges}

@app.get('/api/catalog')
def catalog():
    # Keep curated public web resources distinct from integrations that WireSploit can
    # invoke itself. De-duplicate identical URLs while preserving the richer description.
    resources = []
    seen = set()
    for item in [*WEB_TOOLS, *awesome_catalog()]:
        url = str(item.get('url') or '').strip()
        if not url.startswith(('https://', 'http://')):
            continue
        key = url.rstrip('/').lower()
        if key in seen:
            continue
        seen.add(key)
        resources.append({**item, 'url': url, 'integration': 'external-resource'})
    return sorted(
        resources,
        key=lambda x: (
            str(x.get('category') or x.get('group') or '').lower(),
            str(x.get('name') or '').lower(),
        ),
    )

@app.post('/api/tools/{tid}/repair')
def repair_tool(tid: str, _: bool = Depends(require_same_origin)):
    diagnostic = tooling.diagnose(tid)
    if diagnostic.get('status') == 'unknown':
        raise HTTPException(404, 'Tool not found')
    if not diagnostic.get('repairable'):
        raise HTTPException(400, 'This tool has no automatic install/repair workflow. Open its project link and follow the upstream instructions.')
    return tooling.repair(tid)

@app.get('/api/scopes')
def list_scopes(_: bool = Depends(require_same_origin)):
    return security.list_scopes()

@app.post('/api/scopes')
def add_scope(x: Scope, _: bool = Depends(require_same_origin)):
    try:
        return security.add_scope(x.value, x.label)
    except ValueError as e:
        raise HTTPException(400, str(e))

@app.delete('/api/scopes/{sid}')
def delete_scope(sid: str, _: bool = Depends(require_same_origin)):
    if not security.delete_scope(sid):
        raise HTTPException(404, 'Scope not found')
    return {'ok': True}

# Search History endpoints
class HistoryEntry(BaseModel):
    query: str
    kind: str = 'search'

@app.get('/api/history')
def list_history(limit: int = 50, _: bool = Depends(require_same_origin)):
    return store.get_search_history(limit)

@app.post('/api/history')
def add_history(x: HistoryEntry, _: bool = Depends(require_same_origin)):
    query = x.query.strip()
    if not query:
        raise HTTPException(400, 'Query cannot be empty')
    if len(query) > 500:
        raise HTTPException(400, 'Query too long (max 500 characters)')
    return {'id': store.add_search_history(query, x.kind)}

@app.delete('/api/history/{hid}')
def delete_history(hid: str, _: bool = Depends(require_same_origin)):
    if not store.delete_search_history(hid):
        raise HTTPException(404, 'History entry not found')
    return {'ok': True}

@app.delete('/api/history')
def clear_history(_: bool = Depends(require_same_origin)):
    count = store.clear_search_history()
    return {'ok': True, 'deleted': count}

@app.post('/api/security/snapshot')
async def security_snapshot(x: Scope, _: bool = Depends(require_same_origin)):
    try:
        return await security.web_security_snapshot(x.value)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))

@app.post('/api/security/probe')
async def security_probe(x: Scope, _: bool = Depends(require_same_origin)):
    if not security.is_authorized(x.value):
        raise HTTPException(403, 'Target is not in a saved authorized scope.')
    try:
        return await security.limited_authorized_probe(x.value)
    except ValueError as e:
        raise HTTPException(400, str(e))

@app.get('/api/diagnostics')
def diagnostics(_: bool = Depends(require_same_origin)):
    ts = tooling.list_tools()
    return {
        'system': platform.platform(),
        'python': sys.version,
        'registered': len(ts),
        'ready': sum(t.get('diagnostic', {}).get('status') == 'ready' for t in ts),
        'tools': ts,
    }

@app.post('/api/investigations/{iid}/evidence/upload')
async def upload_evidence(iid: str, file: UploadFile = File(...), kind: str = Form('file'), title: str = Form(''), source: str = Form(''), description: str = Form(''), _: bool = Depends(require_same_origin)):
    # Check investigation exists
    if not store.get_investigation(iid):
        raise HTTPException(404, 'Investigation not found')
    # Read file content
    content = await file.read()
    # Call store.add_evidence with content_bytes and filename
    eid = store.add_evidence(iid, kind, title, source, description, content_bytes=content, filename=file.filename)
    return {'id': eid}

@app.post('/api/screenshot')
async def capture_screenshot(url: str = Form(...), _: bool = Depends(require_same_origin)):
    # Validate URL for SSRF protection (checks authorization, public IPs, redirect validation)
    # Returns (validated_url, pinned_ips) for DNS pinning
    try:
        validated_url, pinned_ips = await security.validate_screenshot_url(url)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))

    # Launch browser, take screenshot, and return as PNG
    # Hardened: DNS pinning via pinned_ips, size limits, timeout limits
    async with async_playwright() as p:
        browser = await p.firefox.launch()
        page = await browser.new_page()

        # Set viewport size limit to prevent huge screenshots (max 4K equivalent)
        await page.set_viewport_size({"width": 1920, "height": 1080})

        # Intercept and validate redirects during navigation using pinned IPs
        async def handle_route(route, request):
            redirect_url = request.url
            try:
                # Validate the redirect destination
                validated_redirect, redirect_ips = await security.validate_screenshot_url(redirect_url)
                # Continue with the validated URL
                await route.continue_()
            except (PermissionError, ValueError) as e:
                # Block the redirect
                await route.abort()
                raise HTTPException(400, f'Redirect blocked: {e}')

        # Note: page.route is async, we need to set it up before goto
        await page.route('**/*', handle_route)

        # Navigate with timeout (30 seconds max)
        await page.goto(validated_url, wait_until="networkidle", timeout=30000)
        # Wait for dynamic content with timeout (5 seconds max)
        await page.wait_for_timeout(5000)

        # Take screenshot with size limit (max 10MB)
        screenshot_bytes = await page.screenshot(full_page=True)
        if len(screenshot_bytes) > 10 * 1024 * 1024:  # 10MB limit
            raise HTTPException(413, 'Screenshot exceeds maximum size limit (10MB)')
        await browser.close()

    # Return the screenshot as a streaming response
    return StreamingResponse(
        io.BytesIO(screenshot_bytes),
        media_type="image/png",
        headers={"Content-Disposition": f"attachment; filename=screenshot.png"}
    )

@app.put('/api/investigations/{iid}/permanent')
def set_investigation_permanent(iid: str, permanent: bool = Form(...), _: bool = Depends(require_same_origin)):
    if not store.get_investigation(iid):
        raise HTTPException(404, 'Investigation not found')
    with store.connect() as c:
        cursor = c.execute('UPDATE investigations SET permanent=? WHERE id=?', (int(permanent), iid))
        if cursor.rowcount == 0:
            raise HTTPException(404, 'Investigation not found')
    return {'id': iid, 'permanent': permanent}


@app.get('/api/evidence/{eid}')
def get_evidence_file(eid: str, _: bool = Depends(require_same_origin)):
    # Get evidence record to verify existence and get metadata
    ev = store.row('SELECT * FROM evidence WHERE id=?', (eid,))
    if not ev:
        raise HTTPException(404, 'Evidence not found')
    # ev columns: id, investigation_id, kind, title, source, url, description, sha256, created_at, filename, mime_type, file_path
    url = ev[5]  # url field (generated filename)
    filename = ev[9] if len(ev) > 9 else None  # original filename
    mime_type = ev[10] if len(ev) > 10 else None  # original mime_type
    if not url:
        raise HTTPException(404, 'No file associated with this evidence')
    # Verify SHA-256 hash matches stored hash
    verified, expected_hash, actual_hash = store.verify_evidence_hash(eid)
    if not verified:
        if expected_hash is None:
            raise HTTPException(404, 'Evidence file not found or no hash to verify')
        else:
            raise HTTPException(409, f'Evidence integrity check failed: expected hash {expected_hash}, got {actual_hash}')
    # Get validated file path (prevents path traversal)
    file_path = store.get_evidence_filepath(eid)
    if not file_path or not file_path.is_file():
        raise HTTPException(404, 'Evidence file not found on disk')
    # Use original filename and mime_type if available, fallback to generated
    download_filename = filename if filename else url
    media_type = mime_type if mime_type else 'application/octet-stream'
    return FileResponse(file_path, media_type=media_type, filename=download_filename)


@app.post('/api/investigations/{iid}/notes')
def add_investigation_note_endpoint(iid: str, note: str = Form(...), _: bool = Depends(require_same_origin)):
    if not store.get_investigation(iid):
        raise HTTPException(404, 'Investigation not found')
    nid = store.add_investigation_note(iid, note)
    return {'id': nid}

@app.get('/api/investigations/{iid}/notes')
def get_investigation_notes_endpoint(iid: str, _: bool = Depends(require_same_origin)):
    if not store.get_investigation(iid):
        raise HTTPException(404, 'Investigation not found')
    notes = store.get_investigation_notes(iid)
    return notes

@app.put('/api/investigations/notes/{nid}')
def update_investigation_note_endpoint(nid: str, note: str = Form(...), _: bool = Depends(require_same_origin)):
    success = store.update_investigation_note(nid, note)
    if not success:
        raise HTTPException(404, 'Note not found')
    return {'id': nid}

@app.delete('/api/investigations/notes/{nid}')
def delete_investigation_note_endpoint(nid: str, _: bool = Depends(require_same_origin)):
    success = store.delete_investigation_note(nid)
    if not success:
        raise HTTPException(404, 'Note not found')
    return {'id': nid}