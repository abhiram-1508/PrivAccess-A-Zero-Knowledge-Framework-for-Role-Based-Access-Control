# PrivAccess Startup
$port = 3000
$proc = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue | Select-Object -First 1
if ($proc) {
    Write-Host "Killing process on port $port"
    Stop-Process -Id $proc.OwningProcess -Force
    Start-Sleep -Seconds 1
}
if (-not (Test-Path "node_modules")) {
    Write-Host "Installing Node dependencies..."
    npm install
}
if (Test-Path "priv_access_rs") {
    Set-Location "priv_access_rs"
    cargo run
} else {
    Write-Host "Error: priv_access_rs folder not found"
    exit 1
}
