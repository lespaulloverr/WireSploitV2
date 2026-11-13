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
from engine.credentials import get_vault, CredentialKind
from engine.kali_env import get_kali_manager, initialize_kali_environment, get_kali_environment_summary, enhance_tool_diagnostics
WEB = ROOT / 'web'
store.init()

app = FastAPI(title='WireSploit', version='4.0.0')
app.mount('/static', StaticFiles(directory=WEB), name='static')

# Track cleanup task for graceful shutdown
cleanup_task = None


@app.on_event("startup")
async def startup_event():
    global cleanup_task

    # Detect if running in PyInstaller bundle
    is_frozen = getattr(sys, 'frozen', False)

    # Install Playwright browsers if not present (skip in frozen executable)
    if not is_frozen:
        def install_browsers():
            try:
                subprocess.run([sys.executable, "-m", "playwright", "install", "firefox"], check=True, capture_output=True)
                print("Playwright Firefox browser installed.")
            except Exception as e:
                print(f"Failed to install Playwright browsers: {e}")
        # Run in a thread to avoid blocking the event loop
        await asyncio.to_thread(install_browsers)
    else:
        print("Running in executable mode - skipping Playwright browser install")

    # Initialize Kali environment detection (non-blocking)
    try:
        kali_env = await initialize_kali_environment()
        print(f"Kali environment detected: {kali_env.env_type.value} - {kali_env.status.value}")
        if kali_env.status.value == "connected":
            print(f"  Kali version: {kali_env.version}")
            print(f"  Hostname: {kali_env.hostname}")
    except Exception as e:
        print(f"Kali environment detection failed: {e}")

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
    validate_person,
    validate_company,
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

ALLOWED_KINDS = {'auto', 'username', 'email', 'phone', 'domain', 'ip', 'person', 'company', 'search'}

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
def investigations(
    search: str = '',
    status: str = '',
    limit: int = 50,
    offset: int = 0,
    _: bool = Depends(require_same_origin)
):
    """List investigations with optional search, filter, and pagination."""
    # Validate limit
    limit = min(max(limit, 1), 200)
    offset = max(offset, 0)

    with store.connect() as c:
        # Build query
        where_clauses = []
        params = []

        if search:
            where_clauses.append('name LIKE ?')
            params.append(f'%{search}%')

        if status:
            where_clauses.append('status = ?')
            params.append(status)

        where_sql = 'WHERE ' + ' AND '.join(where_clauses) if where_clauses else ''

        # Get total count
        count_query = f'SELECT COUNT(*) as cnt FROM investigations {where_sql}'
        total = c.execute(count_query, params).fetchone()['cnt']

        # Get paginated results
        query = f'''
            SELECT * FROM investigations
            {where_sql}
            ORDER BY updated_at DESC
            LIMIT ? OFFSET ?
        '''
        params.extend([limit, offset])
        rows = c.execute(query, params).fetchall()

        return {
            'investigations': [dict(r) for r in rows],
            'total': total,
            'limit': limit,
            'offset': offset,
        }

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
        elif kind == 'person':
            is_valid, normalized, error_msg = validate_person(value)
        elif kind == 'company':
            is_valid, normalized, error_msg = validate_company(value)
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
def tools(classification: str = None):
    """Get all tools, optionally filtered by classification (public endpoint)."""
    ts = tooling.list_tools()
    if classification:
        # Filter by classification
        filtered = []
        for t in ts:
            spec = tooling.SPEC_BY_ID.get(t.get('name', '').lower().replace(' ', '_'))
            if spec and spec.classification.value == classification:
                filtered.append(t)
        return filtered
    return ts

@app.get('/api/tools/classifications')
def tool_classifications(_: bool = Depends(require_same_origin)):
    """Get tools grouped by classification."""
    ts = tooling.list_tools()
    result = {'executable': [], 'restricted': [], 'educational': []}
    for t in ts:
        spec = tooling.SPEC_BY_ID.get(t.get('id'))
        if spec:
            cls = spec.classification.value
            if cls in result:
                # Add classification info to tool
                t['classification'] = cls
                t['kali_category'] = spec.kali_category.value if spec.kali_category else None
                t['risk_level'] = spec.risk_level
                t['authorized_only'] = spec.authorized_only
                t['deep_only'] = spec.deep_only
                result[cls].append(t)
    return result


class ToolExecuteRequest(BaseModel):
    tool_id: str
    target: str
    deep: bool = False
    srm_authorized: bool = False

@app.post('/api/tools/execute')
async def execute_tool(x: ToolExecuteRequest, _: bool = Depends(require_same_origin)):
    """Execute a specific tool against a target."""
    spec = tooling.SPEC_BY_ID.get(x.tool_id)
    if not spec:
        raise HTTPException(404, 'Tool not found')

    # Check authorization for restricted tools
    if spec.authorized_only and not x.srm_authorized:
        raise HTTPException(403, 'This tool requires SRM authorization')

    # Check deep mode requirement
    if spec.deep_only and not x.deep:
        raise HTTPException(400, 'This tool requires deep mode to be enabled')

    # Get the command to execute
    cmd = tooling.tool_command(x.tool_id, x.target, 'domain')  # category defaults to domain for CLI tools
    if not cmd:
        raise HTTPException(400, f'{spec.name} is not installed or ready')

    if len(cmd) == 3:
        cw, wd, stdin = cmd
    else:
        cw, wd = cmd
        stdin = None

    # Execute the command
    timeout = spec.timeout if spec.timeout else 90
    code, out, err = await tooling.run_subprocess(cw, wd, timeout=timeout, stdin_text=stdin)

    if code != 0 and not out:
        raise HTTPException(500, err or f'Exit code {code}')

    # Parse output using the tool's parser
    parser_name = spec.parser
    findings = []
    if parser_name:
        parser_func = getattr(tooling, f'parse_{parser_name}', None)
        if parser_func:
            findings = parser_func(x.tool_id, x.target, out, 'domain')
    else:
        # Fallback to category-based parsers
        findings = tooling.parse_kv_output(x.tool_id, x.target, out, 'domain')

    return {
        'tool_id': x.tool_id,
        'target': x.target,
        'deep': x.deep,
        'exit_code': code,
        'output': out[:5000],  # Truncate output
        'findings': findings
    }

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
    # Enhance tool diagnostics with Kali environment info
    for tool in ts:
        tool_id = tool.get('id')
        if tool_id:
            kali_diag = enhance_tool_diagnostics({tool_id: tool.get('diagnostic', {})})
            if tool_id in kali_diag:
                tool['diagnostic'] = kali_diag[tool_id]

    ready_count = sum(t.get('diagnostic', {}).get('status') == 'ready' for t in ts)

    return {
        'system': platform.platform(),
        'python': sys.version,
        'registered': len(ts),
        'ready': ready_count,
        'tools': ts,
        'kali_environment': get_kali_environment_summary(),
    }


@app.get('/api/kali-environment')
def kali_environment_details(_: bool = Depends(require_same_origin)):
    """Get detailed Kali environment information."""
    return get_kali_environment_summary()


@app.post('/api/kali-environment/rescan')
async def kali_environment_rescan(_: bool = Depends(require_same_origin)):
    """Trigger a rescan of Kali tools."""
    from engine.kali_env import get_kali_manager
    manager = get_kali_manager()
    # Run scan in thread to avoid blocking
    result = await asyncio.to_thread(manager.scan_tools)
    return {
        'ok': True,
        'scanned': len(result),
        'tools': {k: {'available': v.available, 'version': v.version, 'error': v.error} for k, v in result.items()}
    }


# ============================================================
# Credential Vault API Endpoints
# ============================================================

class CredentialStoreRequest(BaseModel):
    name: str
    kind: str
    secret: str
    metadata: dict = {}

class CredentialImportRequest(BaseModel):
    name: str
    kind: str
    metadata: dict = {}

@app.get('/api/credentials')
def list_credentials(kind: str = None, _: bool = Depends(require_same_origin)):
    """List all credentials (metadata only, no secrets)."""
    vault = get_vault()
    return vault.list_credentials(kind)

@app.post('/api/credentials')
def store_credential(x: CredentialStoreRequest, _: bool = Depends(require_same_origin)):
    """Store a new credential in the vault."""
    if not x.name or not x.name.strip():
        raise HTTPException(400, 'Name cannot be empty')
    if not x.kind:
        raise HTTPException(400, 'Kind is required')
    if not x.secret:
        raise HTTPException(400, 'Secret cannot be empty')
    vault = get_vault()
    credential_id = vault.store(x.name.strip(), x.kind, x.secret, x.metadata)
    return {'id': credential_id}

@app.get('/api/credentials/{cred_id}')
def get_credential(cred_id: str, _: bool = Depends(require_same_origin)):
    """Retrieve a credential (returns secret)."""
    vault = get_vault()
    try:
        secret = vault.retrieve(cred_id)
        return {'id': cred_id, 'secret': secret}
    except KeyError:
        raise HTTPException(404, 'Credential not found')
    except ValueError as e:
        raise HTTPException(400, f'Decryption failed: {e}')

@app.delete('/api/credentials/{cred_id}')
def delete_credential(cred_id: str, _: bool = Depends(require_same_origin)):
    """Delete a credential from the vault."""
    vault = get_vault()
    if not vault.delete(cred_id):
        raise HTTPException(404, 'Credential not found')
    return {'ok': True}

@app.get('/api/credentials/{cred_id}/metadata')
def get_credential_metadata(cred_id: str, _: bool = Depends(require_same_origin)):
    """Get metadata for a credential (no secret)."""
    vault = get_vault()
    meta = vault.get_metadata(cred_id)
    if not meta:
        raise HTTPException(404, 'Credential not found')
    return meta

@app.put('/api/credentials/{cred_id}/metadata')
def update_credential_metadata(cred_id: str, metadata: dict, _: bool = Depends(require_same_origin)):
    """Update metadata for a credential."""
    vault = get_vault()
    if not vault.update_metadata(cred_id, metadata):
        raise HTTPException(404, 'Credential not found')
    return {'ok': True}

@app.post('/api/credentials/import')
async def import_credential(x: CredentialImportRequest, file: UploadFile = File(...), _: bool = Depends(require_same_origin)):
    """Import a credential from a file."""
    if not x.name or not x.name.strip():
        raise HTTPException(400, 'Name cannot be empty')
    if not x.kind:
        raise HTTPException(400, 'Kind is required')
    vault = get_vault()
    content = await file.read()
    secret = content.decode('utf-8', errors='replace')
    credential_id = vault.store(x.name.strip(), x.kind, secret, x.metadata)
    return {'id': credential_id}

@app.get('/api/credentials/{cred_id}/export')
def export_credential(cred_id: str, _: bool = Depends(require_same_origin)):
    """Export a credential to a file."""
    vault = get_vault()
    try:
        secret = vault.retrieve(cred_id)
        meta = vault.get_metadata(cred_id)
        filename = f"{meta.get('name', cred_id) if meta else cred_id}.txt"
        return StreamingResponse(
            io.StringIO(secret),
            media_type='text/plain',
            headers={'Content-Disposition': f'attachment; filename={filename}'}
        )
    except KeyError:
        raise HTTPException(404, 'Credential not found')
    except ValueError as e:
        raise HTTPException(400, f'Decryption failed: {e}')

@app.post('/api/credentials/rotate-master-key')
def rotate_master_key(_: bool = Depends(require_same_origin)):
    """Rotate the master key (re-encrypt all credentials)."""
    vault = get_vault()
    success = vault.rotate_master_key()
    if not success:
        raise HTTPException(500, 'Master key rotation failed')
    return {'ok': True}

# Credential kinds for UI
@app.get('/api/credential-kinds')
def get_credential_kinds(_: bool = Depends(require_same_origin)):
    """Get list of available credential kinds."""
    return {
        'kinds': [
            {'value': CredentialKind.WORDLIST, 'label': 'Wordlist'},
            {'value': CredentialKind.API_KEY, 'label': 'API Key'},
            {'value': CredentialKind.HASHCAT_MASK, 'label': 'Hashcat Mask'},
            {'value': CredentialKind.HYDRA_USERLIST, 'label': 'Hydra Userlist'},
            {'value': CredentialKind.SSH_KEY, 'label': 'SSH Key'},
            {'value': CredentialKind.NTLM_HASH, 'label': 'NTLM Hash'},
            {'value': CredentialKind.GENERIC, 'label': 'Generic'},
        ]
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

        # Navigate with timeout (90 seconds max)
        await page.goto(validated_url, wait_until="domcontentloaded", timeout=90000)
        # Wait for dynamic content with timeout (5 seconds max)
        await page.wait_for_timeout(5000)

        # Take screenshot with size limit (max 10MB) and longer timeout for full page
        screenshot_bytes = await page.screenshot(full_page=True, timeout=60000)
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


if __name__ == '__main__':
    import uvicorn
    # When running as PyInstaller executable, use the app object directly
    uvicorn.run(app, host=config['HOST'], port=config['PORT'], reload=False)