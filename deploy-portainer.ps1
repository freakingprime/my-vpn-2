param(
    [string]$Branch = "main",
    [string]$CommitMessage = "feat: my-vpn-2 multi-target Go HTTPS proxy gateway"
)

[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# Read configuration from .env or environment variables
$envFile = Join-Path $PSScriptRoot ".env"
$apiKey = $env:PORTAINER_API_KEY
$portainerUrl = if ($env:PORTAINER_URL) { $env:PORTAINER_URL } else { "https://localhost:9443" }
$endpointId = if ($env:PORTAINER_ENDPOINT_ID) { [int]$env:PORTAINER_ENDPOINT_ID } else { 1 }
$nucDataDir = if ($env:NUC_DATA_DIR) { $env:NUC_DATA_DIR } else { "/opt/my-vpn-2" }
$localSshKeyPath = if ($env:LOCAL_SSH_KEY_PATH) { $env:LOCAL_SSH_KEY_PATH } else { (Join-Path $env:USERPROFILE ".ssh\id_rsa") }
$webPort = if ($env:WEB_PORT) { $env:WEB_PORT } else { "8080" }
$proxyPort = if ($env:PROXY_PORT) { $env:PROXY_PORT } else { "8888" }
$gceHost = if ($env:GCE_HOST) { $env:GCE_HOST } else { "203.0.113.10:22" }
$gceUser = if ($env:GCE_USER) { $env:GCE_USER } else { "cloud-user" }
$gceKeyPath = if ($env:GCE_KEY_PATH) { $env:GCE_KEY_PATH } else { "/data/id_rsa" }

if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith("#") -and $line.Contains("=")) {
            $parts = $line.Split("=", 2)
            $k = $parts[0].Trim()
            $v = $parts[1].Trim().Trim("'`"")
            if ($k -eq "PORTAINER_API_KEY") { $apiKey = $v }
            elseif ($k -eq "PORTAINER_URL") { $portainerUrl = $v }
            elseif ($k -eq "PORTAINER_ENDPOINT_ID") { $endpointId = [int]$v }
            elseif ($k -eq "NUC_DATA_DIR") { $nucDataDir = $v }
            elseif ($k -eq "LOCAL_SSH_KEY_PATH") { $localSshKeyPath = $v }
            elseif ($k -eq "WEB_PORT") { $webPort = $v }
            elseif ($k -eq "PROXY_PORT") { $proxyPort = $v }
            elseif ($k -eq "GCE_HOST") { $gceHost = $v }
            elseif ($k -eq "GCE_USER") { $gceUser = $v }
            elseif ($k -eq "GCE_KEY_PATH") { $gceKeyPath = $v }
        }
    }
}

if (-not $apiKey) {
    Write-Host "PORTAINER_API_KEY not found in .env or environment variables." -ForegroundColor Yellow
    $apiKey = Read-Host "Please enter Portainer API Key"
    if (-not $apiKey) {
        Write-Host "ERROR: Portainer API key is required." -ForegroundColor Red
        exit 1
    }
}

$oldStackName = "vpngate"
$newStackName = "vpngate2"
$imageTag = "ghcr.io/freakingprime/my-vpn-2:latest"
$repoUrl = "https://github.com/freakingprime/my-vpn-2.git"
$nucHost = ([System.Uri]$portainerUrl).Host
$webUrl = "http://${nucHost}:${webPort}"
$proxyUrl = "http://${nucHost}:${proxyPort}"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " my-vpn-2 Automated Portainer Deployment ($nucHost)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Remove old stacks and legacy containers on host
Write-Host "`n[1/5] Cleaning up legacy stacks and containers on $nucHost..." -ForegroundColor Yellow
$stacksRaw = & curl.exe -k -s -H "X-API-Key: $apiKey" "$portainerUrl/api/stacks"
$stacks = $stacksRaw | ConvertFrom-Json
$oldStack = $stacks | Where-Object { $_.Name -eq $oldStackName }
if ($null -ne $oldStack) {
    Write-Host ">> Deleting legacy Portainer stack '$oldStackName' (ID: $($oldStack.Id))..." -ForegroundColor Cyan
    & curl.exe -k -s -X DELETE -H "X-API-Key: $apiKey" "$portainerUrl/api/stacks/$($oldStack.Id)?endpointId=$endpointId" | Out-Null
    Start-Sleep -Seconds 2
}

$containersRaw = & curl.exe -k -s -H "X-API-Key: $apiKey" "$portainerUrl/api/endpoints/$endpointId/docker/containers/json?all=1"
$containers = $containersRaw | ConvertFrom-Json
foreach ($c in $containers) {
    foreach ($n in $c.Names) {
        if ($n -in @("/vpn_manager", "/vpngate_client", "/socks5_proxy", "/vpngate2_controller", "/vpngate2_vpn")) {
            Write-Host ">> Removing legacy container $n..." -ForegroundColor Cyan
            & curl.exe -k -s -X DELETE -H "X-API-Key: $apiKey" "$portainerUrl/api/endpoints/$endpointId/docker/containers/$($c.Id)?v=1&force=1" | Out-Null
        }
    }
}

# 2. Provision host data directory, .env, and SSH key
Write-Host "`n[2/5] Provisioning $nucDataDir, runtime .env, and SSH key on $nucHost..." -ForegroundColor Yellow
if (-not (Test-Path $localSshKeyPath)) {
    Write-Host "ERROR: SSH private key not found at $localSshKeyPath" -ForegroundColor Red
    exit 1
}
$keyB64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($localSshKeyPath))
$keyFileName = [System.IO.Path]::GetFileName($gceKeyPath)

$runtimeEnvText = "WEB_PORT=$webPort`nPROXY_PORT=$proxyPort`nGCE_HOST=$gceHost`nGCE_USER=$gceUser`nGCE_KEY_PATH=$gceKeyPath`n"
$envB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($runtimeEnvText))

$prepCmd = "mkdir -p /host_data && echo '$keyB64' | base64 -d > /host_data/$keyFileName && chmod 600 /host_data/$keyFileName && echo '$envB64' | base64 -d > /host_data/.env && chmod 600 /host_data/.env && touch /host_data/custom.conf && ls -la /host_data"
$prepObj = @{
    Image = "python:3.11-alpine"
    Entrypoint = @("sh", "-c")
    Cmd = @($prepCmd)
    HostConfig = @{
        Binds = @("${nucDataDir}:/host_data:rw")
    }
}
$tmpPrep = [System.IO.Path]::GetTempFileName()
[System.IO.File]::WriteAllText($tmpPrep, ($prepObj | ConvertTo-Json -Depth 5 -Compress), [System.Text.Encoding]::ASCII)
$prepResp = & curl.exe -k -s -X POST -H "X-API-Key: $apiKey" -H "Content-Type: application/json" -d "@$tmpPrep" "$portainerUrl/api/endpoints/$endpointId/docker/containers/create?name=my-vpn-2_prep_tmp" | ConvertFrom-Json
Remove-Item $tmpPrep -Force -ErrorAction SilentlyContinue
if ($prepResp.Id) {
    & curl.exe -k -s -X POST -H "X-API-Key: $apiKey" "$portainerUrl/api/endpoints/$endpointId/docker/containers/$($prepResp.Id)/start" | Out-Null
    Start-Sleep -Seconds 2
    & curl.exe -k -s -X DELETE -H "X-API-Key: $apiKey" "$portainerUrl/api/endpoints/$endpointId/docker/containers/$($prepResp.Id)?v=1&force=1" | Out-Null
    Write-Host ">> Host directory $nucDataDir initialized with .env and $keyFileName." -ForegroundColor Green
}

# 3. Build Docker image directly on host via Docker Build API
Write-Host "`n[3/5] Building Go Docker image '$imageTag' on $nucHost..." -ForegroundColor Yellow
$tarPath = Join-Path ([System.IO.Path]::GetTempPath()) "my-vpn-2_build_ctx.tar.gz"
if (Test-Path $tarPath) { Remove-Item $tarPath -Force }
& tar.exe -czf $tarPath -C $PSScriptRoot Dockerfile go.mod main.go docker-compose.yml

$buildOut = & curl.exe -k -s -X POST -H "X-API-Key: $apiKey" -H "Content-Type: application/x-tar" --data-binary "@$tarPath" "$portainerUrl/api/endpoints/$endpointId/docker/build?t=$imageTag&rm=1"
Remove-Item $tarPath -Force -ErrorAction SilentlyContinue
if ($buildOut -match "Successfully tagged" -or $buildOut -match "Successfully built") {
    Write-Host ">> Successfully compiled and tagged '$imageTag' on $nucHost!" -ForegroundColor Green
} else {
    Write-Host "Build output tail:" -ForegroundColor Gray
    Write-Host ($buildOut | Select-Object -Last 15)
}

# 4. Commit and Push to GitHub (origin/main)
Write-Host "`n[4/5] Committing and pushing source code to GitHub ($repoUrl)..." -ForegroundColor Yellow
Push-Location $PSScriptRoot
if (Test-Path "first.txt") {
    git rm -f "first.txt" 2>$null | Out-Null
}
git add Dockerfile docker-compose.yml go.mod main.go deploy-portainer.ps1 deploy-portainer.cmd README.md .gitignore .env.example synology/ .github/ 2>$null
$dirty = git status --porcelain
if ($dirty) {
    git commit -m "$CommitMessage"
}
git push -u origin $Branch
Pop-Location

# 5. Deploy / Update Stack in Portainer
Write-Host "`n[5/5] Deploying '$newStackName' stack in Portainer..." -ForegroundColor Yellow
$stacksRaw = & curl.exe -k -s -H "X-API-Key: $apiKey" "$portainerUrl/api/stacks"
$stacks = $stacksRaw | ConvertFrom-Json
$existingNew = $stacks | Where-Object { $_.Name -eq $newStackName }
if ($null -ne $existingNew) {
    Write-Host ">> Removing existing '$newStackName' stack (ID: $($existingNew.Id)) for clean redeploy..." -ForegroundColor Cyan
    & curl.exe -k -s -X DELETE -H "X-API-Key: $apiKey" "$portainerUrl/api/stacks/$($existingNew.Id)?endpointId=$endpointId" | Out-Null
    Start-Sleep -Seconds 2
}

$composeContent = [System.IO.File]::ReadAllText((Join-Path $PSScriptRoot "docker-compose.yml"), [System.Text.Encoding]::UTF8)
# Adapt compose file for Portainer standalone deployment using host data dir and .env
$composeForPortainer = ($composeContent -replace "(?m)^\s*build:\s*\.\r?\n", "")
$composeForPortainer = $composeForPortainer.Replace("./data:", "${nucDataDir}:")
$composeForPortainer = $composeForPortainer.Replace("- .env", "- stack.env")

$stackBodyObj = @{
    Name = $newStackName
    StackFileContent = $composeForPortainer
    Env = @(
        @{ name = "WEB_PORT"; value = $webPort },
        @{ name = "PROXY_PORT"; value = $proxyPort },
        @{ name = "GCE_HOST"; value = $gceHost },
        @{ name = "GCE_USER"; value = $gceUser },
        @{ name = "GCE_KEY_PATH"; value = $gceKeyPath }
    )
}
$tmpStack = [System.IO.Path]::GetTempFileName()
[System.IO.File]::WriteAllText($tmpStack, ($stackBodyObj | ConvertTo-Json -Depth 5 -Compress), [System.Text.Encoding]::ASCII)
$deployRespRaw = & curl.exe -k -s -X POST -H "X-API-Key: $apiKey" -H "Content-Type: application/json" -d "@$tmpStack" "$portainerUrl/api/stacks/create/standalone/string?endpointId=$endpointId"
Remove-Item $tmpStack -Force -ErrorAction SilentlyContinue

try {
    $deployResp = $deployRespRaw | ConvertFrom-Json
    if ($deployResp.Id) {
        Write-Host ">> Stack '$newStackName' created in Portainer (Stack ID: $($deployResp.Id))!" -ForegroundColor Green
    } else {
        Write-Host "Portainer response: $deployRespRaw" -ForegroundColor Yellow
    }
} catch {
    Write-Host "Portainer raw response: $deployRespRaw" -ForegroundColor Yellow
}

# Ensure my-vpn-2_vpn (gluetun) is stopped initially since default mode is Direct (Local ISP)
Start-Sleep -Seconds 3
& curl.exe -k -s -X POST -H "X-API-Key: $apiKey" "$portainerUrl/api/endpoints/$endpointId/docker/containers/my-vpn-2_vpn/stop?t=5" | Out-Null

# Verify Web UI & Proxy Health
Write-Host "`nVerifying my-vpn-2 Web UI ($webUrl) and Proxy ($proxyUrl)..." -ForegroundColor Cyan
for ($i = 1; $i -le 15; $i++) {
    Start-Sleep -Seconds 2
    $statusJson = & curl.exe -s --max-time 4 "$webUrl/api/status" 2>$null
    if ($statusJson -and $statusJson.Contains("activeMode")) {
        Write-Host "`n==========================================================" -ForegroundColor Green
        Write-Host " my-vpn-2 DEPLOYED & VERIFIED SUCCESSFULLY!" -ForegroundColor Green
        Write-Host " - Web Dashboard URL:  $webUrl" -ForegroundColor Cyan
        Write-Host " - HTTPS Proxy Server: ${nucHost}:${proxyPort}" -ForegroundColor Cyan
        Write-Host " - Auto-Config (PAC):  $webUrl/proxy.pac" -ForegroundColor Cyan
        Write-Host " - Live API Status:    $statusJson" -ForegroundColor Gray
        Write-Host "==========================================================" -ForegroundColor Green
        break
    }
}
