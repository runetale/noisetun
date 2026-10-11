# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025-2026 Runetale Inc.
# Copyright (C) 2025-2026 gx14ac
#
# Windows benchmark: wg-c vs wireguard-go via Wintun + loopback
#
# Two WireGuard instances on the same host, UDP via loopback (127.0.0.1).
#
#   wintun0 (10.10.0.1) <-> UDP 127.0.0.1:51820 <-> UDP 127.0.0.1:51821 <-> wintun1 (10.10.0.2)
#
# Prerequisites:
#   - wintun.dll in PATH or same directory as wg-c.exe
#   - iperf3.exe in PATH
#   - wg.exe (wireguard-tools) in PATH
#   - Run as Administrator
#
# Usage:
#   .\scripts\bench_windows.ps1 -WgC .\build\Release\wg-c.exe [-WgGo wireguard-go.exe] [-Runs 5] [-Duration 10]
#
# Examples:
#   .\scripts\bench_windows.ps1 -WgC .\build\Release\wg-c.exe
#   .\scripts\bench_windows.ps1 -WgC .\build\Release\wg-c.exe -WgGo wireguard-go.exe -Runs 5 -Duration 30

param(
    [Parameter(Mandatory=$true)]
    [string]$WgC,

    [string]$WgGo = "",

    [int]$Runs = 5,

    [int]$Duration = 10
)

$ErrorActionPreference = "Stop"
$Omit = 3

$PortA = 51820
$PortB = 51821
$WgIpA = "10.10.0.1"
$WgIpB = "10.10.0.2"
$IfaceA = "wg-bench-a"
$IfaceB = "wg-bench-b"

$ResultsDir = "$env:TEMP\bench_windows_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $ResultsDir -Force | Out-Null

function Log($msg) {
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $msg"
}

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# -- Preflight --
if (-not (Test-Admin)) {
    Write-Error "Error: must run as Administrator"
    exit 1
}

if (-not (Test-Path $WgC)) {
    Write-Error "Error: $WgC not found"
    exit 1
}

if (-not (Get-Command "wg.exe" -ErrorAction SilentlyContinue)) {
    Write-Error "Error: wg.exe (wireguard-tools) not found in PATH"
    exit 1
}

if (-not (Get-Command "iperf3.exe" -ErrorAction SilentlyContinue)) {
    Write-Error "Error: iperf3.exe not found in PATH"
    exit 1
}

if ($WgGo -and -not (Test-Path $WgGo) -and -not (Get-Command $WgGo -ErrorAction SilentlyContinue)) {
    Write-Error "Error: $WgGo not found"
    exit 1
}

# -- Key Generation --
function Generate-Keys {
    $script:KeyAPriv = & wg genkey
    $script:KeyAPub = $script:KeyAPriv | & wg pubkey
    $script:KeyBPriv = & wg genkey
    $script:KeyBPub = $script:KeyBPriv | & wg pubkey

    $script:KeyFileA = "$ResultsDir\key_a"
    $script:KeyFileB = "$ResultsDir\key_b"
    Set-Content -Path $script:KeyFileA -Value $script:KeyAPriv -NoNewline
    Set-Content -Path $script:KeyFileB -Value $script:KeyBPriv -NoNewline
}

# -- Configure WireGuard peers --
function Configure-Peers {
    & wg set $IfaceA `
        private-key $script:KeyFileA `
        listen-port $PortA `
        peer $script:KeyBPub `
        endpoint "127.0.0.1:$PortB" `
        allowed-ips "$WgIpB/32"

    & wg set $IfaceB `
        private-key $script:KeyFileB `
        listen-port $PortB `
        peer $script:KeyAPub `
        endpoint "127.0.0.1:$PortA" `
        allowed-ips "$WgIpA/32"

    # Assign IP addresses via netsh
    & netsh interface ip set address $IfaceA static $WgIpA 255.255.255.0
    & netsh interface ip set address $IfaceB static $WgIpB 255.255.255.0

    Start-Sleep -Seconds 2

    # Verify connectivity
    $ping = Test-Connection -ComputerName $WgIpB -Count 2 -Quiet
    if (-not $ping) {
        Log "WARNING: ping to $WgIpB failed, continuing anyway..."
    }
}

# -- Start wg-c pair --
function Start-WgcPair {
    # Ensure no stale adapters remain from a previous run
    $stale = Get-NetAdapter -Name "wg-bench-*" -ErrorAction SilentlyContinue
    if ($stale) {
        Log "WARNING: stale adapters detected, waiting for cleanup..."
        Get-Process -Name "wg-c" -ErrorAction SilentlyContinue | Stop-Process -Force
        for ($w = 0; $w -lt 10; $w++) {
            if (-not (Get-NetAdapter -Name "wg-bench-*" -ErrorAction SilentlyContinue)) { break }
            Start-Sleep -Seconds 1
        }
        if (Get-NetAdapter -Name "wg-bench-*" -ErrorAction SilentlyContinue) {
            Log "Error: cannot clear stale adapters, skipping run"
            return $false
        }
    }

    $script:ProcA = Start-Process -FilePath $WgC -ArgumentList @("-f", $IfaceA) `
        -NoNewWindow -PassThru -RedirectStandardError "$ResultsDir\wgc_a_stderr.txt"

    # Wait for UAPI to become ready
    $ready = $false
    for ($w = 0; $w -lt 10; $w++) {
        Start-Sleep -Seconds 1
        if ($script:ProcA.HasExited) {
            Log "Error: wg-c A exited during startup"
            return $false
        }
        $null = cmd /c "wg show $IfaceA 2>nul"
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
    }
    if (-not $ready) {
        Log "Error: wg-c A UAPI not ready after 10s"
        Stop-Process -Id $script:ProcA.Id -Force -ErrorAction SilentlyContinue
        return $false
    }

    $script:ProcB = Start-Process -FilePath $WgC -ArgumentList @("-f", $IfaceB) `
        -NoNewWindow -PassThru -RedirectStandardError "$ResultsDir\wgc_b_stderr.txt"

    $ready = $false
    for ($w = 0; $w -lt 10; $w++) {
        Start-Sleep -Seconds 1
        if ($script:ProcB.HasExited) {
            Log "Error: wg-c B exited during startup"
            Stop-Process -Id $script:ProcA.Id -Force -ErrorAction SilentlyContinue
            return $false
        }
        $null = cmd /c "wg show $IfaceB 2>nul"
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
    }
    if (-not $ready) {
        Log "Error: wg-c B UAPI not ready after 10s"
        Stop-Process -Id $script:ProcA.Id -Force -ErrorAction SilentlyContinue
        Stop-Process -Id $script:ProcB.Id -Force -ErrorAction SilentlyContinue
        return $false
    }

    Configure-Peers
    return $true
}

# -- Start wireguard-go pair --
function Start-WgGoPair {
    $env:WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD = "1"

    $script:ProcA = Start-Process -FilePath $WgGo -ArgumentList $IfaceA `
        -NoNewWindow -PassThru -RedirectStandardError "$ResultsDir\wggo_a_stderr.txt"
    Start-Sleep -Seconds 2

    $script:ProcB = Start-Process -FilePath $WgGo -ArgumentList $IfaceB `
        -NoNewWindow -PassThru -RedirectStandardError "$ResultsDir\wggo_b_stderr.txt"
    Start-Sleep -Seconds 2

    Configure-Peers
    return $true
}

# -- Stop processes --
function Stop-Pair {
    # Send Ctrl+C via taskkill (allows graceful shutdown)
    if ($script:ProcA -and -not $script:ProcA.HasExited) {
        Stop-Process -Id $script:ProcA.Id -Force -ErrorAction SilentlyContinue
    }
    if ($script:ProcB -and -not $script:ProcB.HasExited) {
        Stop-Process -Id $script:ProcB.Id -Force -ErrorAction SilentlyContinue
    }
    $script:ProcA = $null
    $script:ProcB = $null

    # Kill any lingering wg-c or iperf3
    Get-Process -Name "wg-c" -ErrorAction SilentlyContinue | Stop-Process -Force
    Get-Process -Name "iperf3" -ErrorAction SilentlyContinue | Stop-Process -Force

    # Wait for Wintun adapters to be released by the kernel
    $timeout = 15
    $elapsed = 0
    while ($elapsed -lt $timeout) {
        $adapters = Get-NetAdapter -Name "wg-bench-*" -ErrorAction SilentlyContinue
        if (-not $adapters) { break }
        Start-Sleep -Seconds 1
        $elapsed++
    }
    if ($elapsed -ge $timeout) {
        Log "WARNING: adapters still present after ${timeout}s timeout"
    }

    Start-Sleep -Seconds 2
}

# -- Run single iperf3 test --
function Run-SingleTest {
    param([string]$Impl, [int]$Run)

    $resultFile = "$ResultsDir\${Impl}_run${Run}.json"

    # Start iperf3 server
    $server = Start-Process -FilePath "iperf3.exe" -ArgumentList "-s -B $WgIpB -1" `
        -NoNewWindow -PassThru
    Start-Sleep -Seconds 1

    # Run iperf3 client
    & iperf3.exe -c $WgIpB -B $WgIpA `
        -t $Duration --omit $Omit -P 1 -J `
        | Out-File -FilePath $resultFile -Encoding utf8

    # Wait for server to finish
    if (-not $server.HasExited) {
        Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 500

    # Extract results
    if (Test-Path $resultFile) {
        try {
            $json = Get-Content $resultFile -Raw | ConvertFrom-Json
            $bps = $json.end.sum_sent.bits_per_second
            $gbps = [math]::Round($bps / 1000000000, 3)
            $retrans = if ($json.end.sum_sent.retransmits) { $json.end.sum_sent.retransmits } else { 0 }

            Log "  $Impl run ${Run}: $gbps Gbps, retrans=$retrans"
            Add-Content -Path "$ResultsDir\${Impl}_gbps.txt" -Value $gbps
            Add-Content -Path "$ResultsDir\${Impl}_retrans.txt" -Value $retrans
        } catch {
            Log "  $Impl run ${Run}: FAILED (parse error)"
            Add-Content -Path "$ResultsDir\${Impl}_gbps.txt" -Value "0"
            Add-Content -Path "$ResultsDir\${Impl}_retrans.txt" -Value "-1"
        }
    } else {
        Log "  $Impl run ${Run}: FAILED (no output)"
        Add-Content -Path "$ResultsDir\${Impl}_gbps.txt" -Value "0"
        Add-Content -Path "$ResultsDir\${Impl}_retrans.txt" -Value "-1"
    }
}

# ============================================
# MAIN
# ============================================

Log "==========================================="
Log "   Windows Benchmark: wg-c                 "
Log "==========================================="
Log "  wg-c:     $WgC"
if ($WgGo) { Log "  wg-go:    $WgGo" }
Log "  Runs:     $Runs each"
Log "  Duration: ${Duration}s (--omit ${Omit}s)"
Log "  Results:  $ResultsDir"
Log "==========================================="
Write-Host ""

# Initialize result files
"" | Out-File "$ResultsDir\wgc_gbps.txt" -NoNewline
"" | Out-File "$ResultsDir\wgc_retrans.txt" -NoNewline
if ($WgGo) {
    "" | Out-File "$ResultsDir\wggo_gbps.txt" -NoNewline
    "" | Out-File "$ResultsDir\wggo_retrans.txt" -NoNewline
}

try {
    for ($i = 1; $i -le $Runs; $i++) {
        Log "-------------------------------------------"
        Log "Round $i / $Runs"

        # Randomize order
        $order = if ($WgGo) { Get-Random -Minimum 0 -Maximum 2 } else { 0 }

        if ($order -eq 0) {
            Log "  Order: wg-c first"
        } else {
            Log "  Order: wg-go first"
        }
        Log "-------------------------------------------"

        # wg-c round
        $runWgc = {
            Log "  [wg-c] Setting up..."
            Generate-Keys
            $ok = Start-WgcPair
            if ($ok) {
                Log "  [wg-c] Running iperf3..."
                Run-SingleTest -Impl "wgc" -Run $i
            }
            Stop-Pair
            Start-Sleep -Seconds 1
        }

        # wg-go round
        $runWgGo = {
            Log "  [wg-go] Setting up..."
            Generate-Keys
            $ok = Start-WgGoPair
            if ($ok) {
                Log "  [wg-go] Running iperf3..."
                Run-SingleTest -Impl "wggo" -Run $i
            }
            Stop-Pair
            Start-Sleep -Seconds 1
        }

        if ($order -eq 0) {
            & $runWgc
            if ($WgGo) { & $runWgGo }
        } else {
            & $runWgGo
            & $runWgc
        }
    }
} finally {
    Stop-Pair
}

# ============================================
# SUMMARY
# ============================================

Write-Host ""
Log "==========================================="
Log "              RESULTS                       "
Log "==========================================="
Write-Host ""

function Show-Stats {
    param([string]$File, [string]$Label)

    if (-not (Test-Path $File)) {
        Write-Host "$Label : NO RESULTS"
        return $null
    }

    $values = Get-Content $File | Where-Object { $_ -and $_ -ne "0" } | ForEach-Object { [double]$_ }
    if ($values.Count -eq 0) {
        Write-Host "$Label : NO VALID RESULTS"
        return $null
    }

    $sorted = $values | Sort-Object
    $sum = ($values | Measure-Object -Sum).Sum
    $avg = [math]::Round($sum / $values.Count, 3)
    $min = $sorted[0]
    $max = $sorted[-1]
    $mid = [math]::Floor($values.Count / 2)
    $median = $sorted[$mid]

    Write-Host "$Label :"
    Write-Host "  Count:  $($values.Count)"
    Write-Host "  Mean:   $avg Gbps"
    Write-Host "  Median: $median Gbps"
    Write-Host "  Min:    $min Gbps"
    Write-Host "  Max:    $max Gbps"

    return $avg
}

Write-Host "=== wg-c ==="
$wgcMean = Show-Stats -File "$ResultsDir\wgc_gbps.txt" -Label "wg-c"
Write-Host ""
Write-Host "Retransmissions per run:"
if (Test-Path "$ResultsDir\wgc_retrans.txt") {
    Get-Content "$ResultsDir\wgc_retrans.txt" | ForEach-Object -Begin { $n=1 } -Process { Write-Host "  $n`t$_"; $n++ }
}
Write-Host ""

if ($WgGo -and (Test-Path "$ResultsDir\wggo_gbps.txt")) {
    Write-Host "=== wg-go ==="
    $wggoMean = Show-Stats -File "$ResultsDir\wggo_gbps.txt" -Label "wg-go"
    Write-Host ""
    Write-Host "Retransmissions per run:"
    if (Test-Path "$ResultsDir\wggo_retrans.txt") {
        Get-Content "$ResultsDir\wggo_retrans.txt" | ForEach-Object -Begin { $n=1 } -Process { Write-Host "  $n`t$_"; $n++ }
    }
    Write-Host ""

    if ($wgcMean -and $wggoMean -and $wggoMean -gt 0) {
        $ratio = [math]::Round($wgcMean / $wggoMean * 100, 1)
        Write-Host "=== COMPARISON ==="
        Write-Host "  wg-c mean:   $wgcMean Gbps"
        Write-Host "  wg-go mean:  $wggoMean Gbps"
        Write-Host "  Ratio:       ${ratio}% (wg-c / wg-go)"
    }
}

Write-Host ""
Log "Raw results saved to: $ResultsDir"
Log "Done."
