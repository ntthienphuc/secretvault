$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$pythonPath = Join-Path $projectRoot '.venv\Scripts\python.exe'
& $pythonPath -m PyInstaller --noconfirm --onedir --windowed --name SecretVaultOnline --collect-all webview --collect-all pythonnet --collect-all clr_loader cloud_client_app.py
if ($LASTEXITCODE -ne 0) { throw 'Cloud client build failed' }
$compiler = Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'
& $compiler 'packaging\cloud-client.iss'
if ($LASTEXITCODE -ne 0) { throw 'Cloud client installer failed' }
Get-FileHash -Algorithm SHA256 -LiteralPath 'release\SecretVault-Online-Setup-3.2.0-x64.exe'
