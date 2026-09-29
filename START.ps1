$ErrorActionPreference='Stop'
Set-Location -LiteralPath $PSScriptRoot
if(-not (Get-Command python -ErrorAction SilentlyContinue)){Write-Host 'Python 3 is required.' -ForegroundColor Red; exit 1}
python -m pip install -r requirements.txt
Start-Process 'http://127.0.0.1:8765/'
python -m uvicorn main:app --host 127.0.0.1 --port 8765
