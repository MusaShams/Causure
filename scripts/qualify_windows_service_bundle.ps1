[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BundlePath,

    [Parameter(Mandatory = $true)]
    [string]$ReportPath,

    [ValidateRange(1024, 65535)]
    [int]$Port = 18082,

    [switch]$KeepArtifacts
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$qualificationRoot = "C:\ProgramData\CausureBundleQualification"
$serviceName = "CausureTeam"
$servicePrincipal = "NT SERVICE\CausureTeam"
$packageVersion = "0.4.0a15"
$runtimePath = "C:\Program Files\Causure\Team\$packageVersion"
$receiptPath = "C:\ProgramData\Causure\windows-service-installation.json"
$receiptBackupPath = (
    "C:\ProgramData\Causure\windows-service-installation.removal-backup.json"
)
$installedManifestPath = "C:\ProgramData\Causure\windows-service-bundle-manifest.json"
$publicTenantId = "72f988bf-86f1-41af-91ab-2d7cd011db47"
$startedAt = [DateTimeOffset]::UtcNow
$stage = "preflight"
$passed = $false
$failureType = $null
$failureMessage = $null
$failureNativeOutput = $null
$removeOutput = $null
$rootCreated = $false
$bundleRemovalCompleted = $false
$serviceAbsentAfterCleanup = $false
$runtimeAbsentAfterCleanup = $false
$receiptAbsentAfterCleanup = $false
$receiptBackupAbsentAfterCleanup = $false
$rootRemovedAfterCleanup = $false
$evidence = [ordered]@{}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Executable
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $Arguments) {
        $null = $startInfo.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw [InvalidOperationException]::new("native process did not start")
        }
        $standardOutputTask = $process.StandardOutput.ReadToEndAsync()
        $standardErrorTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $standardOutput = $standardOutputTask.GetAwaiter().GetResult().TrimEnd()
        $standardError = $standardErrorTask.GetAwaiter().GetResult().TrimEnd()
        $output = $standardOutput
        if (-not [string]::IsNullOrWhiteSpace($standardError)) {
            if (-not [string]::IsNullOrWhiteSpace($output)) {
                $output += "`n"
            }
            $output += $standardError
        }
        return [pscustomobject]@{
            exit_code = $process.ExitCode
            output = $output
        }
    }
    catch {
        return [pscustomobject]@{
            exit_code = $null
            output = "native process start failed: $($_.Exception.GetType().Name)"
        }
    }
    finally {
        $process.Dispose()
    }
}

function Invoke-CheckedNative {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$Operation
    )

    $invocation = Invoke-NativeCapture -Executable $Executable -Arguments $Arguments
    if ($invocation.exit_code -ne 0) {
        $exitDescription = if ($null -eq $invocation.exit_code) {
            "not started"
        }
        else {
            [string]$invocation.exit_code
        }
        throw [InvalidOperationException]::new(
            "$Operation failed: $exitDescription"
        )
    }
    return $invocation.output
}

function Invoke-ServiceCli {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $python = Join-Path $runtimePath "python.exe"
    return Invoke-CheckedNative `
        -Executable $python `
        -Arguments (@("-I", "-B", "-m", "causure.team_windows_service_cli") + $Arguments) `
        -Operation "Causure Windows service command"
}

function Wait-ServiceAbsent {
    param([ValidateRange(1, 60)][int]$Seconds = 20)

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($Seconds)
    do {
        if ($null -eq (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
            return $true
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    return $false
}

function Wait-ServiceStopped {
    param([ValidateRange(1, 120)][int]$Seconds = 60)

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($Seconds)
    do {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -eq $service -or $service.Status -eq "Stopped") {
            return $true
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    return $false
}

function Wait-Ready {
    param([ValidateRange(1, 240)][int]$Seconds = 60)

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($Seconds)
    do {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -eq $service -or $service.Status -eq "Stopped") {
            throw [InvalidOperationException]::new("service stopped before readiness")
        }
        try {
            $health = Invoke-WebRequest `
                -Uri "http://127.0.0.1:$Port/healthz" `
                -SkipHttpErrorCheck `
                -TimeoutSec 2
            $ready = Invoke-WebRequest `
                -Uri "http://127.0.0.1:$Port/readyz" `
                -SkipHttpErrorCheck `
                -TimeoutSec 2
            if ($health.StatusCode -eq 200 -and $ready.StatusCode -eq 200) {
                return [ordered]@{
                    health_status = [int]$health.StatusCode
                    readiness_status = [int]$ready.StatusCode
                }
            }
        }
        catch {
            # Startup and crash recovery intentionally have short connection gaps.
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw [TimeoutException]::new("service did not become healthy and ready")
}

function Invoke-ExpectedStartFailure {
    param([Parameter(Mandatory = $true)][string]$FailureName)

    $python = Join-Path $runtimePath "python.exe"
    $output = @(& $python `
        -I `
        -B `
        -m causure.team_windows_service_cli start 2>&1)
    $exitCode = $LASTEXITCODE
    if (-not (Wait-ServiceStopped -Seconds 75)) {
        throw [TimeoutException]::new("$FailureName did not reach a stopped state")
    }
    Start-Sleep -Seconds 5
    if ((Get-Service -Name $serviceName).Status -ne "Stopped") {
        throw [InvalidOperationException]::new("$FailureName entered a restart loop")
    }
    return [ordered]@{
        cli_exit_code = $exitCode
        stopped_without_loop = $true
        output_redacted = (-not (($output -join "`n") -match "Authorization|token"))
    }
}

try {
    if (-not (Test-IsAdministrator)) {
        throw [UnauthorizedAccessException]::new("bundle qualification requires elevation")
    }
    foreach ($fixedPath in @(
            $qualificationRoot,
            $runtimePath,
            $receiptPath,
            $receiptBackupPath,
            $installedManifestPath
        )) {
        if (Test-Path -LiteralPath $fixedPath) {
            throw [InvalidOperationException]::new("a fixed qualification target already exists")
        }
    }
    if ($null -ne (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
        throw [InvalidOperationException]::new("the fixed Windows service already exists")
    }
    if ($null -ne (Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue)) {
        throw [InvalidOperationException]::new("the qualification port is already in use")
    }

    $resolvedBundle = (Resolve-Path -LiteralPath $BundlePath).Path
    if ([IO.Path]::GetExtension($resolvedBundle) -ne ".zip") {
        throw [InvalidDataException]::new("qualification bundle must be a ZIP file")
    }
    $resolvedReport = [IO.Path]::GetFullPath($ReportPath)
    $reportParent = Split-Path -Parent $resolvedReport
    if (-not (Test-Path -LiteralPath $reportParent -PathType Container)) {
        throw [IO.DirectoryNotFoundException]::new("report parent directory does not exist")
    }
    if ($resolvedReport.StartsWith($qualificationRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw [InvalidOperationException]::new("report must be outside the disposable root")
    }

    $stage = "inspect_archive"
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($resolvedBundle)
    try {
        if ($archive.Entries.Count -lt 4 -or $archive.Entries.Count -gt 20000) {
            throw [InvalidDataException]::new("bundle entry count is unsupported")
        }
        [int64]$totalBytes = 0
        $archivePaths = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
        foreach ($entry in $archive.Entries) {
            $totalBytes += $entry.Length
            if (
                [string]::IsNullOrWhiteSpace($entry.FullName) -or
                $entry.FullName.Contains("\") -or
                $entry.FullName.Contains(":") -or
                $entry.FullName.StartsWith("/", [StringComparison]::Ordinal) -or
                @($entry.FullName.Split("/") | Where-Object { $_ -in @("", ".", "..") }).Count -ne 0 -or
                -not $archivePaths.Add($entry.FullName)
            ) {
                throw [InvalidDataException]::new("bundle archive contains an unsafe entry")
            }
        }
        if ($totalBytes -gt 1GB) {
            throw [InvalidDataException]::new("bundle expands beyond the qualification limit")
        }
    }
    finally {
        $archive.Dispose()
    }

    $bundleHash = (Get-FileHash -LiteralPath $resolvedBundle -Algorithm SHA256).Hash.ToLowerInvariant()
    $bundleRoot = Join-Path $qualificationRoot "bundle"
    $configRoot = Join-Path $qualificationRoot "config"
    $stateRoot = Join-Path $qualificationRoot "state"
    $dataRoot = Join-Path $qualificationRoot "data"
    $null = New-Item -ItemType Directory -Path $bundleRoot, $configRoot, $stateRoot, $dataRoot
    $rootCreated = $true
    Expand-Archive -LiteralPath $resolvedBundle -DestinationPath $bundleRoot

    $manifestPath = Join-Path $bundleRoot "bundle-manifest.json"
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($manifest.package_version -ne $packageVersion) {
        throw [InvalidDataException]::new("bundle package version mismatch")
    }
    $manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()

    $stage = "write_configuration"
    $issuer = "https://login.microsoftonline.com/$publicTenantId/v2.0"
    $jwksUri = "https://login.microsoftonline.com/$publicTenantId/discovery/v2.0/keys"
    $refreshPath = Join-Path $configRoot "entra-refresh.json"
    $hostPath = Join-Path $configRoot "team-host.json"
    $refreshDocument = [ordered]@{
        schema_version = "1.0"
        store_id = "entra-bundle-qualification"
        snapshot_ttl_seconds = 3600
        tenants = @(
            [ordered]@{
                entra_tenant_id = $publicTenantId
                team_tenant_id = "tenant-bundle-qualification"
                issuer = $issuer
                jwks_uri = $jwksUri
                audience = "33333333-3333-4333-8333-333333333333"
                allowed_client_ids = @("44444444-4444-4444-8444-444444444444")
                accepted_delegated_scopes = @("Causure.Access")
                accepted_application_roles = @("Causure.Service")
                max_token_lifetime_seconds = 7200
            }
        )
    }
    $utf8 = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText($refreshPath, ($refreshDocument | ConvertTo-Json -Depth 10), $utf8)
    $refreshBytes = [IO.File]::ReadAllBytes($refreshPath)
    $refreshSha256 = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($refreshBytes)
    ).ToLowerInvariant()
    $hostDocument = [ordered]@{
        schema_version = "1.0"
        database = [ordered]@{
            path = (Join-Path $dataRoot "team.sqlite3")
            busy_timeout_ms = 5000
        }
        server = [ordered]@{
            implementation = "waitress"
            version = "3.0.2"
            listen_host = "127.0.0.1"
            listen_port = $Port
            trusted_external_scheme = "https"
            threads = 4
            connection_limit = 32
            backlog = 32
            channel_timeout_seconds = 30
            max_request_header_bytes = 32768
        }
        identity = [ordered]@{
            refresh_configuration_path = $refreshPath
            refresh_configuration_sha256 = $refreshSha256
            refresh_configuration_byte_count = $refreshBytes.Length
            trust_store_path = (Join-Path $stateRoot "entra-trust.json")
            store_id = "entra-bundle-qualification"
            clock_skew_seconds = 60
            refresh_timeout_seconds = 10
            refresh_interval_seconds = 3600
            failure_retry_seconds = 300
            unknown_key_refresh_seconds = 300
        }
        admission = [ordered]@{
            max_concurrency = 4
            global_requests_per_window = 600
            per_source_requests_per_window = $null
            rate_window_seconds = 60
            max_tracked_sources = 4096
            source_idle_seconds = 600
        }
    }
    [IO.File]::WriteAllText($hostPath, ($hostDocument | ConvertTo-Json -Depth 10), $utf8)
    $hostBytes = [IO.File]::ReadAllBytes($hostPath)
    $hostSha256 = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($hostBytes)
    ).ToLowerInvariant()
    $operatorAclSubjects = @(
        $hostPath,
        $configRoot,
        $refreshPath,
        $stateRoot,
        $dataRoot
    ) | Select-Object -Unique
    $operatorAclBefore = @{}
    foreach ($operatorAclSubject in $operatorAclSubjects) {
        $operatorAcl = Get-Acl -LiteralPath $operatorAclSubject
        $operatorAclBefore[$operatorAclSubject] = $operatorAcl.GetSecurityDescriptorSddlForm(
            [Security.AccessControl.AccessControlSections]::Access
        )
    }

    $stage = "install_bundle"
    $installerPath = Join-Path $bundleRoot "install.ps1"
    $installOutput = @(& pwsh `
        -NoProfile `
        -File $installerPath `
        -HostConfigurationPath $hostPath `
        -ManualStart 2>&1) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        throw [InvalidOperationException]::new("bundle installer failed")
    }
    if (
        -not (Test-Path -LiteralPath $runtimePath -PathType Container) -or
        -not (Test-Path -LiteralPath $receiptPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $installedManifestPath -PathType Leaf)
    ) {
        throw [InvalidOperationException]::new("bundle installation is incomplete")
    }
    $receipt = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
    if (
        $receipt.manifest_sha256 -ne $manifestHash -or
        $receipt.host_configuration_sha256 -ne $hostSha256 -or
        $receipt.automatic_start -ne $false -or
        $receipt.removal_started -ne $false
    ) {
        throw [InvalidDataException]::new("installed receipt does not bind exact inputs")
    }

    $stage = "validate_recovery"
    $recovery = (Invoke-ServiceCli -Arguments @("recovery-status")) | ConvertFrom-Json
    if (
        $recovery.reset_period_seconds -ne 900 -or
        $recovery.apply_on_non_crash_failures -ne $true -or
        @($recovery.actions).Count -ne 2 -or
        $recovery.actions[0].action -ne "restart" -or
        $recovery.actions[0].delay_milliseconds -ne 120000 -or
        $recovery.actions[1].action -ne "none" -or
        $recovery.actions[1].delay_milliseconds -ne 0
    ) {
        throw [InvalidOperationException]::new("SCM recovery policy is not exact")
    }

    $stage = "initial_start"
    $null = Invoke-ServiceCli -Arguments @("start")
    $initialReadiness = Wait-Ready -Seconds 60
    $initialCim = Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'"
    $initialPid = [int]$initialCim.ProcessId
    if ($initialPid -le 0) {
        throw [InvalidOperationException]::new("SCM did not expose the service process ID")
    }

    $stage = "crash_recovery"
    $crashStarted = [DateTimeOffset]::UtcNow
    Stop-Process -Id $initialPid -Force
    $recoveryDeadline = $crashStarted.AddSeconds(210)
    $recoveredPid = 0
    do {
        $recoveredCim = Get-CimInstance `
            -ClassName Win32_Service `
            -Filter "Name='$serviceName'" `
            -ErrorAction SilentlyContinue
        if (
            $null -ne $recoveredCim -and
            $recoveredCim.State -eq "Running" -and
            [int]$recoveredCim.ProcessId -gt 0 -and
            [int]$recoveredCim.ProcessId -ne $initialPid
        ) {
            $recoveredPid = [int]$recoveredCim.ProcessId
            break
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTimeOffset]::UtcNow -lt $recoveryDeadline)
    if ($recoveredPid -le 0) {
        throw [TimeoutException]::new("SCM did not perform the configured crash restart")
    }
    $recoveryElapsedSeconds = ([DateTimeOffset]::UtcNow - $crashStarted).TotalSeconds
    if ($recoveryElapsedSeconds -lt 110) {
        throw [InvalidOperationException]::new("SCM restarted before the bounded delay")
    }
    $recoveredReadiness = Wait-Ready -Seconds 60
    $null = Invoke-ServiceCli -Arguments @("stop")

    $stage = "bound_adversarial_recovery"
    $runtimePython = Join-Path $runtimePath "python.exe"
    $null = Invoke-CheckedNative `
        -Executable $runtimePython `
        -Arguments @(
            "-I",
            "-B",
            "-c",
            ("import win32service as s; " +
                "m=s.OpenSCManager(None,None,s.SC_MANAGER_CONNECT); " +
                "h=s.OpenService(m,'CausureTeam'," +
                "s.SERVICE_QUERY_CONFIG|s.SERVICE_CHANGE_CONFIG); " +
                "s.ChangeServiceConfig2(h,s.SERVICE_CONFIG_FAILURE_ACTIONS," +
                "{'ResetPeriod':900,'RebootMsg':None,'Command':None," +
                "'Actions':((s.SC_ACTION_NONE,0),)}); " +
                "s.ChangeServiceConfig2(h,s.SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,True); " +
                "s.CloseServiceHandle(h); s.CloseServiceHandle(m)")
        ) `
        -Operation "qualification-only recovery bounding"

    $stage = "configuration_drift_failure"
    [IO.File]::WriteAllBytes($hostPath, $hostBytes + [byte]10)
    $configurationDrift = Invoke-ExpectedStartFailure -FailureName "configuration drift"
    [IO.File]::WriteAllBytes($hostPath, $hostBytes)
    $null = Invoke-ServiceCli -Arguments @("configure", $hostPath)

    $stage = "port_collision_failure"
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
    try {
        $listener.Start()
        $portCollision = Invoke-ExpectedStartFailure -FailureName "port collision"
    }
    finally {
        $listener.Stop()
    }

    $stage = "restore_recovery_policy"
    $restoredRecovery = (Invoke-ServiceCli -Arguments @("recovery-set")) | ConvertFrom-Json
    if (
        $restoredRecovery.actions[0].action -ne "restart" -or
        $restoredRecovery.actions[0].delay_milliseconds -ne 120000 -or
        $restoredRecovery.actions[1].action -ne "none"
    ) {
        throw [InvalidOperationException]::new("exact recovery policy was not restored")
    }

    $stage = "post_failure_readiness"
    $null = Invoke-ServiceCli -Arguments @("start")
    $finalReadiness = Wait-Ready -Seconds 60

    $stage = "remove_running_bundle"
    $removerPath = Join-Path $runtimePath "management\remove.ps1"
    $removeInvocation = Invoke-NativeCapture `
        -Executable (Get-Command pwsh).Source `
        -Arguments @("-NoProfile", "-File", $removerPath)
    $removeOutput = $removeInvocation.output
    if ($removeInvocation.exit_code -ne 0) {
        throw [InvalidOperationException]::new("bundle remover failed")
    }
    $bundleRemovalCompleted = $true
    if (
        -not (Wait-ServiceAbsent -Seconds 20) -or
        (Test-Path -LiteralPath $runtimePath) -or
        (Test-Path -LiteralPath $receiptPath) -or
        (Test-Path -LiteralPath $receiptBackupPath) -or
        (Test-Path -LiteralPath $installedManifestPath)
    ) {
        throw [InvalidOperationException]::new("bundle remover left machine-managed state")
    }
    $operatorPathsPreserved = (
        (Test-Path -LiteralPath $hostPath -PathType Leaf) -and
        (Test-Path -LiteralPath $refreshPath -PathType Leaf) -and
        (Test-Path -LiteralPath $stateRoot -PathType Container) -and
        (Test-Path -LiteralPath $dataRoot -PathType Container)
    )
    if (-not $operatorPathsPreserved) {
        throw [InvalidOperationException]::new("bundle remover deleted operator-owned state")
    }
    $operatorAclsRestored = $true
    foreach ($operatorAclSubject in $operatorAclSubjects) {
        $operatorAcl = Get-Acl -LiteralPath $operatorAclSubject
        $accessSddl = $operatorAcl.GetSecurityDescriptorSddlForm(
            [Security.AccessControl.AccessControlSections]::Access
        )
        if ($accessSddl -ne $operatorAclBefore[$operatorAclSubject]) {
            $operatorAclsRestored = $false
            break
        }
    }
    if (-not $operatorAclsRestored) {
        throw [InvalidOperationException]::new("bundle remover did not restore operator ACLs")
    }

    $evidence = [ordered]@{
        schema_version = "1.0"
        result = "passed"
        os = [ordered]@{
            caption = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
            version = [Environment]::OSVersion.Version.ToString()
            build = [Environment]::OSVersion.Version.Build
        }
        bundle = [ordered]@{
            package_version = $packageVersion
            bundle_sha256 = $bundleHash
            manifest_sha256 = $manifestHash
            manifest_file_count = @($manifest.files).Count
            closed_install_verified = ($installOutput -match '"result": "installed"')
        }
        installation = [ordered]@{
            machine_runtime_path = $runtimePath
            receipt_bound_manifest = $true
            receipt_bound_host_configuration = $true
            manual_start = $true
            service_account = $servicePrincipal
            exact_recovery_policy = $true
        }
        lifecycle = [ordered]@{
            initial_health_status = $initialReadiness.health_status
            initial_readiness_status = $initialReadiness.readiness_status
            crash_initial_pid = $initialPid
            crash_recovered_pid = $recoveredPid
            crash_recovery_elapsed_seconds = [Math]::Round($recoveryElapsedSeconds, 3)
            recovered_health_status = $recoveredReadiness.health_status
            recovered_readiness_status = $recoveredReadiness.readiness_status
            configuration_drift_failed_closed = $configurationDrift.stopped_without_loop
            configuration_drift_output_redacted = $configurationDrift.output_redacted
            port_collision_failed_closed = $portCollision.stopped_without_loop
            port_collision_output_redacted = $portCollision.output_redacted
            adversarial_failure_recovery_actions = "qualification-temporary-none"
            exact_recovery_restored_after_adversarial_failures = $true
            post_failure_health_status = $finalReadiness.health_status
            post_failure_readiness_status = $finalReadiness.readiness_status
            remover_stopped_running_service = ($removeOutput -match '"result": "removed"')
        }
        removal = [ordered]@{
            service_absent = $true
            runtime_absent = $true
            receipt_absent = $true
            receipt_backup_absent = $true
            installed_manifest_absent = $true
            operator_paths_preserved = $operatorPathsPreserved
            operator_acls_restored = $operatorAclsRestored
        }
        cold_boot = [ordered]@{
            performed = $false
            reason = "reboot requires separate explicit operator authorization"
        }
    }
    $passed = $true
}
catch {
    $failureType = $_.Exception.GetType().Name
    $failureMessage = $_.Exception.Message
    if (
        $stage -eq "remove_running_bundle" -and
        -not [string]::IsNullOrWhiteSpace($removeOutput)
    ) {
        $failureNativeOutput = $removeOutput.Substring(
            0,
            [Math]::Min(2048, $removeOutput.Length)
        )
    }
}
finally {
    $stageBeforeCleanup = $stage
    $stage = "cleanup"
    $cleanupErrors = [Collections.Generic.List[string]]::new()
    try {
        $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -ne $existingService) {
            $cleanupPython = Join-Path $runtimePath "python.exe"
            if (
                $existingService.Status -ne "Stopped" -and
                (Test-Path -LiteralPath $cleanupPython)
            ) {
                $stopInvocation = Invoke-NativeCapture `
                    -Executable $cleanupPython `
                    -Arguments @(
                        "-I",
                        "-B",
                        "-m",
                        "causure.team_windows_service_cli",
                        "stop"
                    )
                if ($stopInvocation.exit_code -ne 0) {
                    $cleanupErrors.Add("service CLI stop failed")
                }
            }
            $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($null -ne $existingService -and $existingService.Status -ne "Stopped") {
                $scStop = Invoke-NativeCapture `
                    -Executable "$env:SystemRoot\System32\sc.exe" `
                    -Arguments @("stop", $serviceName)
                if ($scStop.exit_code -ne 0) {
                    $cleanupErrors.Add("SCM stop fallback failed")
                }
                if (-not (Wait-ServiceStopped -Seconds 60)) {
                    $cleanupErrors.Add("service remained active during cleanup")
                }
            }
            $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($null -ne $existingService -and $existingService.Status -eq "Stopped") {
                if (Test-Path -LiteralPath $cleanupPython) {
                    $removeInvocation = Invoke-NativeCapture `
                        -Executable $cleanupPython `
                        -Arguments @(
                            "-I",
                            "-B",
                            "-m",
                            "causure.team_windows_service_cli",
                            "remove"
                        )
                    if ($removeInvocation.exit_code -ne 0) {
                        $cleanupErrors.Add("service CLI removal failed")
                    }
                }
                if ($null -ne (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
                    $scDelete = Invoke-NativeCapture `
                        -Executable "$env:SystemRoot\System32\sc.exe" `
                        -Arguments @("delete", $serviceName)
                    if ($scDelete.exit_code -ne 0) {
                        $cleanupErrors.Add("SCM delete fallback failed")
                    }
                }
            }
        }
        $serviceAbsentAfterCleanup = Wait-ServiceAbsent -Seconds 20
    }
    catch {
        $cleanupErrors.Add(
            "service cleanup failed: $($_.Exception.GetType().Name)"
        )
    }

    if ($serviceAbsentAfterCleanup) {
        foreach ($managedPath in @(
                $runtimePath,
                $receiptPath,
                $receiptBackupPath,
                $installedManifestPath
            )) {
            if (Test-Path -LiteralPath $managedPath) {
                try {
                    if (
                        $managedPath -eq $runtimePath -and
                        [string]::Equals(
                            (Resolve-Path -LiteralPath $managedPath).Path,
                            $runtimePath,
                            [StringComparison]::OrdinalIgnoreCase
                        )
                    ) {
                        Remove-Item `
                            -LiteralPath $managedPath `
                            -Recurse `
                            -Force `
                            -ErrorAction Stop
                    }
                    elseif ($managedPath -in @(
                            $receiptPath,
                            $receiptBackupPath,
                            $installedManifestPath
                        )) {
                        Remove-Item -LiteralPath $managedPath -Force -ErrorAction Stop
                    }
                    else {
                        $cleanupErrors.Add("managed cleanup path did not match its fixed path")
                    }
                }
                catch {
                    $cleanupErrors.Add(
                        "managed path cleanup failed: $($_.Exception.GetType().Name)"
                    )
                }
            }
        }
    }
    $runtimeAbsentAfterCleanup = -not (Test-Path -LiteralPath $runtimePath)
    $receiptAbsentAfterCleanup = -not (Test-Path -LiteralPath $receiptPath)
    $receiptBackupAbsentAfterCleanup = -not (Test-Path -LiteralPath $receiptBackupPath)

    if (
        $rootCreated -and
        $serviceAbsentAfterCleanup -and
        $runtimeAbsentAfterCleanup -and
        -not $KeepArtifacts -and
        (Test-Path -LiteralPath $qualificationRoot)
    ) {
        try {
            $resolvedQualificationRoot = (Resolve-Path -LiteralPath $qualificationRoot).Path
            if (-not [string]::Equals(
                    $resolvedQualificationRoot,
                    $qualificationRoot,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                throw [InvalidOperationException]::new(
                    "refusing to remove an unexpected qualification path"
                )
            }
            Remove-Item `
                -LiteralPath $resolvedQualificationRoot `
                -Recurse `
                -Force `
                -ErrorAction Stop
        }
        catch {
            $cleanupErrors.Add(
                "qualification root cleanup failed: $($_.Exception.GetType().Name)"
            )
        }
    }
    $rootRemovedAfterCleanup = -not (Test-Path -LiteralPath $qualificationRoot)

    if (-not $passed) {
        $evidence = [ordered]@{
            schema_version = "1.0"
            result = "failed"
            failed_stage = $stageBeforeCleanup
            failure_type = $failureType
            failure_message = $failureMessage
            failure_native_output = $failureNativeOutput
        }
    }
    $evidence.started_at_utc = $startedAt.ToString("O")
    $evidence.finished_at_utc = [DateTimeOffset]::UtcNow.ToString("O")
    $evidence.cleanup = [ordered]@{
        service_absent = $serviceAbsentAfterCleanup
        runtime_absent = $runtimeAbsentAfterCleanup
        receipt_absent = $receiptAbsentAfterCleanup
        receipt_backup_absent = $receiptBackupAbsentAfterCleanup
        qualification_root_removed = $rootRemovedAfterCleanup
        errors = @($cleanupErrors)
    }
    [IO.File]::WriteAllText(
        [IO.Path]::GetFullPath($ReportPath),
        ($evidence | ConvertTo-Json -Depth 10),
        [Text.UTF8Encoding]::new($false)
    )
}

if (
    -not $passed -or
    -not $serviceAbsentAfterCleanup -or
    -not $runtimeAbsentAfterCleanup -or
    -not $receiptAbsentAfterCleanup -or
    -not $receiptBackupAbsentAfterCleanup -or
    $cleanupErrors.Count -ne 0 -or
    (-not $KeepArtifacts -and -not $rootRemovedAfterCleanup)
) {
    exit 1
}

$evidence | ConvertTo-Json -Depth 10
