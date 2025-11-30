# generate-cert.ps1
# Self-signed ECC certificate generator using OpenSSL in WSL only

# ------------------------------
# Step 1: Resolve .env and domain
# ------------------------------
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$envFilePath = Join-Path $projectRoot ".env"

$DomainName = $env:COMPUTERNAME

if (Test-Path $envFilePath) {
    try {
        $envContent = Get-Content $envFilePath
        foreach ($line in $envContent) {
            if ($line -match '^\s*DOMAIN_NAME\s*=\s*(.+?)\s*$') {
                $DomainName = $Matches[1].Trim().ToLower()
                break
            }
        }
    } catch {
        Write-Warning "Could not read .env file. Using computer name as fallback."
    }
}

Write-Host "Using domain: $DomainName"

# ------------------------------
# Step 2: Setup output paths
# ------------------------------
$certDir = Join-Path $PSScriptRoot "certs"
$outputKeyPath = Join-Path $certDir "private.key"
$outputCrtPath = Join-Path $certDir "certificate.crt"
$confPath = Join-Path $PSScriptRoot "openssl.tmp.cnf"

if (-not (Test-Path $certDir)) {
    New-Item -ItemType Directory -Path $certDir | Out-Null
}

if ((Test-Path $outputKeyPath) -and (Test-Path $outputCrtPath)) {
    Write-Host "Certificate files already exist in '$certDir'. Skipping generation."
    exit 0
}

# ------------------------------
# Step 3: Subject Alternative Names (SAN)
# ------------------------------
$fqdn = if ($DomainName -like "*.*") { $DomainName } else { "$DomainName.local" }

$dnsNames = @($DomainName)
if ($DomainName -ne $fqdn) { $dnsNames += $fqdn }

$ipAddresses = Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -notlike '127.*' -and $_.PrefixOrigin -ne 'WellKnown' } |
    Select-Object -ExpandProperty IPAddress

if ($ipAddresses) {
    Write-Host "Including IPs in SAN: $($ipAddresses -join ', ')"
}

$sanDnsList = $dnsNames | ForEach-Object -Begin { $i = 1 } -Process { "DNS.$i = $_"; $i++ }
$sanIpList = $ipAddresses | ForEach-Object -Begin { $i = 1 } -Process { "IP.$i = $_"; $i++ }

# ------------------------------
# Step 4: Generate OpenSSL config
# ------------------------------
$opensslConfContent = @"
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no
[req_distinguished_name]
CN = $DomainName
O = IAMClient4D
OU = IT Department - Dev Team
L = Bergamo
ST = Lombardia
C = IT
[v3_req]
subjectAltName = @alt_names
[alt_names]
$($sanDnsList -join "`r`n")
$($sanIpList -join "`r`n")
"@
Set-Content -Path $confPath -Value $opensslConfContent -Encoding ASCII

# ------------------------------
# Step 5: WSL path conversion
# ------------------------------
function Convert-ToWslPath {
    param (
        [Parameter(Mandatory = $true)]
        [string]$winPath
    )

    try {
        $fullPath = [System.IO.Path]::GetFullPath($winPath)
    } catch {
        Write-Error "Invalid Windows path: $winPath"
        return $null
    }

    $wslPath = wsl wslpath -a "`"$fullPath`"" 2>$null
    if ([string]::IsNullOrWhiteSpace($wslPath)) {
        Write-Error "wslpath failed to convert path: $fullPath"
        return $null
    }

    return $wslPath.Trim()
}

$wslKeyPath = Convert-ToWslPath $outputKeyPath
$wslCrtPath = Convert-ToWslPath $outputCrtPath
$wslConfPath = Convert-ToWslPath $confPath

if (-not $wslKeyPath -or -not $wslCrtPath -or -not $wslConfPath) {
    Write-Error "One or more paths could not be converted to WSL format. Aborting."
    exit 1
}

# ------------------------------
# Step 6: Validate OpenSSL in WSL
# ------------------------------
try {
    $version = wsl openssl version 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "OpenSSL not available in WSL."
    } else {
        Write-Host "Using WSL OpenSSL: $version"
    }
} catch {
    Write-Error "OpenSSL is not available in WSL. Aborting."
    exit 1
}

# ------------------------------
# Step 7: Generate key and certificate
# ------------------------------
Write-Host "Generating ECC private key..."
wsl openssl ecparam -name prime256v1 -genkey -noout -out "$wslKeyPath"

Write-Host "Generating self-signed certificate..."
wsl openssl req -x509 -new -key "$wslKeyPath" -out "$wslCrtPath" -days 365 -config "$wslConfPath" -extensions v3_req

# ------------------------------
# Step 8: Cleanup and summary
# ------------------------------
Remove-Item $confPath

Write-Host "`n✅ Process completed!"
Write-Host "Certificate files generated in '$certDir':"
Write-Host " - Private Key : $outputKeyPath"
Write-Host " - Certificate : $outputCrtPath"