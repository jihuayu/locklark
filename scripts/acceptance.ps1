# Windows CLI acceptance. Only synthetic data; leaves a fresh temporary directory for inspection.
$ErrorActionPreference = "Stop"
$repo = Split-Path $PSScriptRoot -Parent
Push-Location $repo
try {
    $work = Join-Path ([IO.Path]::GetTempPath()) ("locklark-check-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $work | Out-Null
    $exe = Join-Path $work "locklark.exe"
    go build -trimpath -o $exe ./cmd/locklark
    if ($LASTEXITCODE -ne 0) { throw "Go build failed" }
    function Invoke-Ok([string[]]$argv) {
        $output = & $exe @argv
        if ($LASTEXITCODE -ne 0) { throw "CLI failed: $($argv[0])" }
        $output | ConvertFrom-Json
    }
    $out = Join-Path $work "scenario"
    $null = Invoke-Ok @("demo","--out",$out,"--session","release-1","--reason","synthetic review")
    $one = Join-Path $out "share/epoch-1"
    $two = Join-Path $out "share/epoch-2"
    $a = Join-Path $out "clients/A"
    $b = Join-Path $out "clients/B"
    $before = Invoke-Ok @("inspect","--bundle",$one,"--device",$a,"--epoch","1")
    $after = Invoke-Ok @("inspect","--bundle",$two,"--device",$b,"--epoch","2")
    if ($before.epoch -ne 1 -or $after.items -ne 2 -or $after.attachments -ne 1) { throw "Fixture summary mismatch" }
    $attack = Join-Path $work "isolated-A"
    New-Item -ItemType Directory -Path $attack | Out-Null
    Copy-Item -LiteralPath $two -Destination (Join-Path $attack "snapshot") -Recurse
    Copy-Item -LiteralPath $a -Destination (Join-Path $attack "client") -Recurse
    # Invoke as a separate process; stdout must stay empty when the revoked device fails.
    $denied = & $exe inspect --bundle (Join-Path $attack "snapshot") --device (Join-Path $attack "client") --epoch 2 2>$null
    if ($LASTEXITCODE -eq 0 -or $denied) { throw "Revoked device read the new snapshot" }
    $audit = Invoke-Ok @("audit","--bundle",$two,"--device",$b,"--epoch","2","--session","release-1")
    if ($audit.result -ne "denied" -or $audit.reason -ne "synthetic review") { throw "Audit mismatch" }
    $spool = Join-Path $out "inbox"
    $pub = Join-Path $out "agent/approval.pub"
    $receipt = Invoke-Ok @("request","--inbox",$spool,"--recipient",$pub,"--session","offline-1","--reason","synthetic offline request","--ref","op://synthetic-vault/login-sample/ops/otp-demo")
    $mail = Invoke-Ok @("inbox","--inbox",$spool,"--device",$b,"--session","offline-1")
    if ($receipt.state -ne "pending" -or $mail.requests.Length -ne 1 -or $mail.requests[0].id -ne $receipt.id -or $mail.unreadable -ne 0) { throw "Offline inbox mismatch" }
    "PASS: old A opens v1; isolated A fails v2; B opens v2; signed denial and pending request verified. Synthetic files: $work"
} finally { Pop-Location }
