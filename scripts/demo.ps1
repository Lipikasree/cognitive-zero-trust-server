$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $repo

$compose = @("compose", "--env-file", ".env", "-f", "deploy/docker-compose.yml")
& docker @compose ps
if ($LASTEXITCODE -ne 0) { throw "Docker Compose is unavailable or the stack is not running." }

Write-Host "`n1) Normal command through the gateway (expected: czt-demo)"
& ssh.exe -p 2222 -i ".\keys\alice_client" -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL alice@127.0.0.1 "whoami"
if ($LASTEXITCODE -ne 0) { throw "Normal SSH-through-gateway check failed." }

Write-Host "`n2) Sensitive command with a deliberate NO step-up response (the target command must be blocked)"
$previousPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$denial = "NO" | & ssh.exe -p 2222 -i ".\keys\alice_client" -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL alice@127.0.0.1 "cat /etc/shadow" 2>&1 | Out-String
$ErrorActionPreference = $previousPreference
Write-Host $denial.Trim()
if ($denial -notmatch "CZTS BLOCK") { throw "Expected the gateway to deny the sensitive target command." }

Write-Host "`n3) Recent session IDs and labels"
& python -m czt.admin.cli sessions
Write-Host "`nGrafana: http://localhost:3000 (CZTS folder). The alert sink records a restricted-session alert locally after Grafana evaluates the rule."
