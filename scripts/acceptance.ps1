#requires -Version 7.0
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
    $sessionKey = Join-Path $work "runner.sessionkey"
    $identity = Invoke-Ok @("session-keygen","--out",$sessionKey)
    $null = Invoke-Ok @("session-enroll","--device",$b,"--session","offline-1","--public",$identity.public,"--reason","acceptance runner")
    $receipt = Invoke-Ok @("request","--session-key",$sessionKey,"--inbox",$spool,"--recipient",$pub,"--session","offline-1","--reason","synthetic offline request","--ref","op://synthetic-vault/login-sample/ops/otp-demo")
    $mail = Invoke-Ok @("inbox","--inbox",$spool,"--device",$b,"--session","offline-1")
    if ($mail.requests[0].sender_status -ne "verified" -or $receipt.state -ne "pending" -or $mail.requests.Length -ne 1 -or $mail.requests[0].id -ne $receipt.id -or $mail.unreadable -ne 0) { throw "Offline inbox mismatch" }
    $decision = Invoke-Ok @("decide","--device",$b,"--bundle",(Join-Path $out "share/epoch-3"),"--inbox",$spool,"--id",$receipt.id,"--review",$mail.requests[0].review,"--choice","approve","--reason","verified synthetic metadata")
    $history = Invoke-Ok @("decisions","--device",$b,"--session","offline-1")
    if ($decision.result -ne "approved" -or -not $decision.expires -or $history.request.id -ne $receipt.id -or $history.reason -ne "verified synthetic metadata") {throw "Persistent decision mismatch"}
    $attempt = Join-Path $work "client-attempt"
    $ticket = Join-Path $attempt "invocation.age"
    $hostPublic = Join-Path $out "agent/host-sign.pub"
    $null = Invoke-Ok @("invoke-prepare","--session-key",$sessionKey,"--recipient",$pub,"--host-sign-key",$hostPublic,"--session","offline-1","--id",$receipt.id,"--review",$receipt.review,"--attempt",$attempt)
    $occupied = Join-Path $work "occupied.age"
    [IO.File]::WriteAllText($occupied,"keep")
    $problem = & $exe invoke-run --device $b --bundle (Join-Path $out "share/epoch-3") --ticket $ticket --out $occupied 2>&1
    if ($LASTEXITCODE -eq 0 -or "$problem" -notmatch "output already exists" -or [IO.File]::ReadAllText($occupied) -ne "keep") {throw "Output preflight did not preserve existing file"}
    $workers = @(foreach ($index in 1..2) {
        $start = [Diagnostics.ProcessStartInfo]::new($exe)
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        foreach ($argument in @("invoke-run","--device",$b,"--bundle",(Join-Path $out "share/epoch-3"),"--ticket",$ticket,"--out",(Join-Path $work "worker-$index.age"))) { $start.ArgumentList.Add($argument) }
        [Diagnostics.Process]::Start($start)
    })
    $ok = 0
    foreach ($worker in $workers) {
        if (-not $worker.WaitForExit(30000)) { throw "Redemption timed out" }
        if ($worker.ExitCode -eq 0) { $ok++ }
        $worker.Dispose()
    }
    if ($ok -ne 1) {throw "Expected exactly one successful execution"}
    $cached = Join-Path $work "recovered.age"
    $null = Invoke-Ok @("invoke-receipt","--device",$b,"--ticket",$ticket,"--out",$cached)
    $value = Invoke-Ok @("invoke-result","--attempt",$attempt,"--reply",$cached)
    if ($value.field -ne "otp-demo" -or $value.kind -ne "totp" -or $value.epoch -ne 3) {throw "Scoped metadata reply mismatch"}
    $uses = Invoke-Ok @("executions","--device",$b,"--session","offline-1")
    if ($uses.state -ne "succeeded") {throw "Execution outcome missing"}
    $null = Invoke-Ok @("session-revoke","--device",$b,"--session","offline-1","--reason","runner finished")
    $closed = Invoke-Ok @("inbox","--inbox",$spool,"--device",$b,"--session","offline-1")
    if ($closed.requests[0].sender_status -ne "revoked" -or $closed.requests[0].state -eq "approved") {throw "Session revocation not effective"}
    $prKey = Join-Path $work "pull.sessionkey"
    $prIdentity = Invoke-Ok @("session-keygen","--out",$prKey)
    $null = Invoke-Ok @("pull-enroll","--device",$b,"--session","pull-1","--public",$prIdentity.public,"--reason","check pull status","--repo","example/tools","--repo-id","123")
    $plan = Join-Path $work "proposal.json"
    '{"repo":"123","number":7}' | bun run ./plugins/github-pull-reader/index.ts | Set-Content -LiteralPath $plan -Encoding utf8NoBOM
    if ($LASTEXITCODE -ne 0) {throw "Bun proposal failed"}
    $pr = Invoke-Ok @("pull-request","--session-key",$prKey,"--inbox",$spool,"--recipient",$pub,"--session","pull-1","--reason","check merge","--repo","example/tools","--repo-id","123","--pr","7","--proposal",$plan)
    $seen = Invoke-Ok @("inbox","--inbox",$spool,"--device",$b,"--session","pull-1")
    if ($seen.requests[0].sender_status -ne "verified" -or $seen.requests[0].pull.number -ne 7) {throw "Owner cannot verify target"}
    $null = Invoke-Ok @("decide","--device",$b,"--bundle",(Join-Path $out "share/epoch-3"),"--inbox",$spool,"--id",$pr.id,"--review",$seen.requests[0].review,"--choice","approve","--reason","only this pull")
    $prAttempt=Join-Path $work "pr-attempt"
    $null = Invoke-Ok @("invoke-prepare","--session-key",$prKey,"--recipient",$pub,"--host-sign-key",$hostPublic,"--session","pull-1","--id",$pr.id,"--review",$pr.review,"--attempt",$prAttempt)
    $prReply=Join-Path $work "pr-reply.age"
    $recording=Join-Path $work "recording.json"
    '{"number":7,"state":"open","merged_at":null,"base":{"repo":{"id":123}},"body":"not for the agent"}' | Set-Content -LiteralPath $recording -Encoding utf8NoBOM
    $null = Invoke-Ok @("invoke-run","--device",$b,"--bundle",(Join-Path $out "share/epoch-3"),"--ticket",(Join-Path $prAttempt "invocation.age"),"--out",$prReply,"--recorded-response",$recording)
    $result = Invoke-Ok @("invoke-result","--attempt",$prAttempt,"--reply",$prReply)
    $log = Invoke-Ok @("executions","--device",$b,"--session","pull-1")
    if($result.source -ne "recorded-response/v1" -or $result.pull.number -ne 7 -or $result.pull.state -ne "open" -or $log.pull.number -ne 7 -or $log.pull.backend -ne $result.source){throw "Recorded PR receipt and audit disagree"}
    "PASS: session and device revocation, offline approval, two-process single execution, signed reply recovery and scoped recorded PR. Synthetic files: $work"
} finally { Pop-Location }
