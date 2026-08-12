[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SourcePythonRoot,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$WheelPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ReportPath,

    [ValidateRange(1024, 65535)]
    [int]$Port = 18080,

    [switch]$KeepArtifacts
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$qualificationRoot = "C:\ProgramData\CausureQualification"
$serviceName = "CausureTeam"
$serviceDisplayName = "Causure Team Service"
$servicePrincipal = "NT SERVICE\CausureTeam"
$publicTenantId = "72f988bf-86f1-41af-91ab-2d7cd011db47"
$startedAt = [DateTimeOffset]::UtcNow
$stage = "preflight"
$rootCreated = $false
$serviceInstalled = $false
$adapterRemovedService = $false
$serviceAbsentAfterCleanup = $false
$rootRemovedAfterCleanup = $false
$passed = $false
$failureType = $null
$evidence = [ordered]@{}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
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

    $output = @(& $Executable @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw [InvalidOperationException]::new("$Operation failed with exit code $LASTEXITCODE")
    }
    return ($output -join "`n")
}

function Invoke-ServiceCli {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PythonExecutable,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    return Invoke-CheckedNative `
        -Executable $PythonExecutable `
        -Arguments (@("-m", "causure.team_windows_service_cli") + $Arguments) `
        -Operation "Causure Windows service command"
}

function Wait-ServiceAbsent {
    param([ValidateRange(1, 60)][int]$Seconds = 15)

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
    param([ValidateRange(1, 90)][int]$Seconds = 45)

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($Seconds)
    do {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -eq $service -or $service.Status -eq [ServiceProcess.ServiceControllerStatus]::Stopped) {
            return $true
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    return $false
}

function Grant-CheckedAcl {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Grant,

        [switch]$Recursive
    )

    $arguments = @($Path, "/grant:r", $Grant, "/Q")
    if ($Recursive) {
        $arguments += @("/T", "/C")
    }
    $null = Invoke-CheckedNative `
        -Executable "$env:SystemRoot\System32\icacls.exe" `
        -Arguments $arguments `
        -Operation "service ACL grant"
}

try {
    if (-not (Test-IsAdministrator)) {
        throw [UnauthorizedAccessException]::new("live service qualification requires elevation")
    }
    if ($null -ne (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
        throw [InvalidOperationException]::new("the fixed qualification service already exists")
    }
    if (Test-Path -LiteralPath $qualificationRoot) {
        throw [InvalidOperationException]::new("the fixed qualification directory already exists")
    }
    if ($null -ne (Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue)) {
        throw [InvalidOperationException]::new("the requested loopback port is already in use")
    }

    $sourceRoot = (Resolve-Path -LiteralPath $SourcePythonRoot).Path
    $sourcePython = Join-Path $sourceRoot "python.exe"
    if (-not (Test-Path -LiteralPath $sourcePython -PathType Leaf)) {
        throw [InvalidOperationException]::new("source Python root does not contain python.exe")
    }
    $resolvedWheel = (Resolve-Path -LiteralPath $WheelPath).Path
    if ([IO.Path]::GetExtension($resolvedWheel) -ne ".whl") {
        throw [InvalidOperationException]::new("qualification package must be a wheel")
    }
    $resolvedReport = [IO.Path]::GetFullPath($ReportPath)
    $reportParent = Split-Path -Parent $resolvedReport
    if (-not (Test-Path -LiteralPath $reportParent -PathType Container)) {
        throw [InvalidOperationException]::new("report parent directory does not exist")
    }
    if ($resolvedReport.StartsWith($qualificationRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw [InvalidOperationException]::new("report must be outside the disposable qualification root")
    }

    $stage = "stage_runtime"
    $runtimeRoot = Join-Path $qualificationRoot "runtime"
    $configRoot = Join-Path $qualificationRoot "config"
    $stateRoot = Join-Path $qualificationRoot "state"
    $dataRoot = Join-Path $qualificationRoot "data"
    $null = New-Item -ItemType Directory -Path $runtimeRoot, $configRoot, $stateRoot, $dataRoot
    $rootCreated = $true

    $robocopyArguments = @(
        $sourceRoot,
        $runtimeRoot,
        "/E",
        "/COPY:DAT",
        "/DCOPY:DAT",
        "/R:1",
        "/W:1",
        "/NFL",
        "/NDL",
        "/NJH",
        "/NJS",
        "/NP"
    )
    $null = & "$env:SystemRoot\System32\robocopy.exe" @robocopyArguments
    if ($LASTEXITCODE -gt 7) {
        throw [InvalidOperationException]::new("runtime copy failed with exit code $LASTEXITCODE")
    }

    $qualificationPython = Join-Path $runtimeRoot "python.exe"
    $stage = "install_wheel"
    $null = Invoke-CheckedNative `
        -Executable $qualificationPython `
        -Arguments @("-m", "pip", "install", "--no-deps", "--force-reinstall", $resolvedWheel) `
        -Operation "qualification wheel installation"

    $stage = "validate_runtime"
    $runtimeEvidenceText = Invoke-CheckedNative `
        -Executable $qualificationPython `
        -Arguments @(
            "-c",
            ("import importlib.metadata as m,json,sys,win32serviceutil; " +
                "from causure.constants import PACKAGE_VERSION; " +
                "from causure.team_host import TEAM_HOST_WAITRESS_VERSION; " +
                "from causure.team_windows_service import TEAM_WINDOWS_SERVICE_DEPENDENCY_VERSION; " +
                "print(json.dumps({'python':sys.version.split()[0]," +
                "'causure':m.version('causure')," +
                "'pywin32':m.version('pywin32')," +
                "'waitress':m.version('waitress')," +
                "'package_contract':PACKAGE_VERSION," +
                "'pywin32_contract':TEAM_WINDOWS_SERVICE_DEPENDENCY_VERSION," +
                "'waitress_contract':TEAM_HOST_WAITRESS_VERSION," +
                "'service_executable':win32serviceutil.LocatePythonServiceExe()}))")
        ) `
        -Operation "qualification runtime validation"
    $runtimeEvidence = $runtimeEvidenceText | ConvertFrom-Json
    if ($runtimeEvidence.causure -ne $runtimeEvidence.package_contract) {
        throw [InvalidOperationException]::new("qualification package version mismatch")
    }
    if ($runtimeEvidence.pywin32 -ne $runtimeEvidence.pywin32_contract) {
        throw [InvalidOperationException]::new("qualification pywin32 version mismatch")
    }
    if ($runtimeEvidence.waitress -ne $runtimeEvidence.waitress_contract) {
        throw [InvalidOperationException]::new("qualification Waitress version mismatch")
    }
    $expectedServiceExecutable = Join-Path $runtimeRoot "pythonservice.exe"
    if (-not [string]::Equals(
            [IO.Path]::GetFullPath($runtimeEvidence.service_executable),
            [IO.Path]::GetFullPath($expectedServiceExecutable),
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw [InvalidOperationException]::new("pythonservice.exe is outside the isolated runtime")
    }

    $stage = "write_configuration"
    $issuer = "https://login.microsoftonline.com/$publicTenantId/v2.0"
    $jwksUri = "https://login.microsoftonline.com/$publicTenantId/discovery/v2.0/keys"
    $refreshPath = Join-Path $configRoot "entra-refresh.json"
    $hostPath = Join-Path $configRoot "team-host.json"
    $refreshDocument = [ordered]@{
        schema_version = "1.0"
        store_id = "entra-qualification"
        snapshot_ttl_seconds = 3600
        tenants = @(
            [ordered]@{
                entra_tenant_id = $publicTenantId
                team_tenant_id = "tenant-qualification"
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
    [IO.File]::WriteAllText(
        $refreshPath,
        ($refreshDocument | ConvertTo-Json -Depth 10),
        $utf8
    )
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
            version = $runtimeEvidence.waitress_contract
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
            store_id = "entra-qualification"
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
    [IO.File]::WriteAllText(
        $hostPath,
        ($hostDocument | ConvertTo-Json -Depth 10),
        $utf8
    )
    $hostBytes = [IO.File]::ReadAllBytes($hostPath)
    $hostSha256 = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($hostBytes)
    ).ToLowerInvariant()

    $stage = "install_service"
    $installOutput = Invoke-ServiceCli `
        -PythonExecutable $qualificationPython `
        -Arguments @("install", $hostPath, "--manual-start")
    $serviceInstalled = $true

    $stage = "grant_service_access"
    Grant-CheckedAcl -Path $qualificationRoot -Grant "${servicePrincipal}:(RX)"
    Grant-CheckedAcl `
        -Path $runtimeRoot `
        -Grant "${servicePrincipal}:(OI)(CI)(RX)" `
        -Recursive
    Grant-CheckedAcl -Path $configRoot -Grant "${servicePrincipal}:(OI)(CI)(RX)" -Recursive
    Grant-CheckedAcl -Path $stateRoot -Grant "${servicePrincipal}:(OI)(CI)(M)" -Recursive
    Grant-CheckedAcl -Path $dataRoot -Grant "${servicePrincipal}:(OI)(CI)(M)" -Recursive

    $stage = "validate_registration"
    $serviceCim = Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'"
    if ($null -eq $serviceCim) {
        throw [InvalidOperationException]::new("installed service is not visible through CIM")
    }
    if ($serviceCim.DisplayName -ne $serviceDisplayName) {
        throw [InvalidOperationException]::new("service display name mismatch")
    }
    if ($serviceCim.StartName -ne $servicePrincipal) {
        throw [InvalidOperationException]::new("service identity mismatch")
    }
    if ($serviceCim.StartMode -ne "Manual") {
        throw [InvalidOperationException]::new("qualification service is not demand-start")
    }
    if ($serviceCim.PathName -notlike "*$expectedServiceExecutable*") {
        throw [InvalidOperationException]::new("SCM image path is outside the isolated runtime")
    }

    $sidOutput = @(& "$env:SystemRoot\System32\sc.exe" qsidtype $serviceName 2>&1) -join "`n"
    if ($LASTEXITCODE -ne 0 -or $sidOutput -notmatch "UNRESTRICTED") {
        throw [InvalidOperationException]::new("service SID type is not unrestricted")
    }
    $registrationPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName\Parameters"
    $registrationText = Get-ItemPropertyValue `
        -LiteralPath $registrationPath `
        -Name "HostConfigurationSubject"
    $registration = $registrationText | ConvertFrom-Json
    if (
        $registration.configuration_path -ne $hostPath -or
        $registration.configuration_sha256 -ne $hostSha256 -or
        [int64]$registration.configuration_byte_count -ne $hostBytes.Length
    ) {
        throw [InvalidOperationException]::new("SCM host-configuration subject mismatch")
    }

    $stage = "validate_recovery"
    $recoveryText = Invoke-ServiceCli `
        -PythonExecutable $qualificationPython `
        -Arguments @("recovery-status")
    $recovery = $recoveryText | ConvertFrom-Json
    if (
        $recovery.reset_period_seconds -ne 900 -or
        $recovery.apply_on_non_crash_failures -ne $true -or
        @($recovery.actions).Count -ne 2 -or
        $recovery.actions[0].action -ne "restart" -or
        $recovery.actions[0].delay_milliseconds -ne 120000 -or
        $recovery.actions[1].action -ne "none" -or
        $recovery.actions[1].delay_milliseconds -ne 0 -or
        $recovery.reboot_message_configured -ne $false -or
        $recovery.command_configured -ne $false
    ) {
        throw [InvalidOperationException]::new("SCM recovery policy mismatch")
    }

    $stage = "start_service"
    $startOutput = Invoke-ServiceCli `
        -PythonExecutable $qualificationPython `
        -Arguments @("start")

    $stage = "wait_for_readiness"
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(45)
    $healthResponse = $null
    $readyResponse = $null
    do {
        $currentService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -eq $currentService -or $currentService.Status -eq "Stopped") {
            throw [InvalidOperationException]::new("service stopped before readiness")
        }
        try {
            $healthResponse = Invoke-WebRequest `
                -Uri "http://127.0.0.1:$Port/healthz" `
                -SkipHttpErrorCheck `
                -TimeoutSec 2
            $readyResponse = Invoke-WebRequest `
                -Uri "http://127.0.0.1:$Port/readyz" `
                -SkipHttpErrorCheck `
                -TimeoutSec 2
            if ($healthResponse.StatusCode -eq 200 -and $readyResponse.StatusCode -eq 200) {
                break
            }
        }
        catch {
            $healthResponse = $null
            $readyResponse = $null
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    if (
        $null -eq $healthResponse -or
        $null -eq $readyResponse -or
        $healthResponse.StatusCode -ne 200 -or
        $readyResponse.StatusCode -ne 200
    ) {
        throw [TimeoutException]::new("service did not become healthy and ready")
    }
    $runningCim = Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'"

    $stage = "stop_service"
    $stopOutput = Invoke-ServiceCli `
        -PythonExecutable $qualificationPython `
        -Arguments @("stop")
    $stoppedService = Get-Service -Name $serviceName
    if ($stoppedService.Status -ne "Stopped") {
        throw [InvalidOperationException]::new("service did not reach stopped state")
    }

    $stage = "remove_service"
    $removeOutput = Invoke-ServiceCli `
        -PythonExecutable $qualificationPython `
        -Arguments @("remove")
    $adapterRemovedService = $true
    if (-not (Wait-ServiceAbsent -Seconds 15)) {
        throw [TimeoutException]::new("adapter removal left the service registered")
    }
    $serviceInstalled = $false

    $evidence = [ordered]@{
        schema_version = "1.0"
        result = "passed"
        os = [ordered]@{
            caption = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
            version = [Environment]::OSVersion.Version.ToString()
            build = [Environment]::OSVersion.Version.Build
        }
        runtime = [ordered]@{
            python = $runtimeEvidence.python
            causure = $runtimeEvidence.causure
            pywin32 = $runtimeEvidence.pywin32
            waitress = $runtimeEvidence.waitress
            isolated_service_executable = $true
        }
        package = [ordered]@{
            wheel_sha256 = (Get-FileHash -LiteralPath $resolvedWheel -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        registration = [ordered]@{
            service_name = $serviceName
            display_name = $serviceCim.DisplayName
            account = $serviceCim.StartName
            start_mode = $serviceCim.StartMode
            sid_type = "UNRESTRICTED"
            host_configuration_sha256 = $hostSha256
            host_configuration_byte_count = $hostBytes.Length
            exact_subject_matched = $true
        }
        recovery = [ordered]@{
            reset_period_seconds = $recovery.reset_period_seconds
            first_action = $recovery.actions[0].action
            first_delay_milliseconds = $recovery.actions[0].delay_milliseconds
            second_action = $recovery.actions[1].action
            apply_on_non_crash_failures = $recovery.apply_on_non_crash_failures
            command_or_reboot_configured = $false
        }
        lifecycle = [ordered]@{
            install_left_stopped = ($installOutput -match "service is stopped")
            scm_running = ($runningCim.State -eq "Running")
            health_status = [int]$healthResponse.StatusCode
            readiness_status = [int]$readyResponse.StatusCode
            stop_reached_stopped = ($stoppedService.Status -eq "Stopped")
            adapter_removed_service = $adapterRemovedService
        }
    }
    $passed = $true
}
catch {
    $failureType = $_.Exception.GetType().Name
}
finally {
    $stageBeforeCleanup = $stage
    $stage = "cleanup"
    $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($null -ne $existingService) {
        if ($existingService.Status -ne "Stopped") {
            $null = & "$env:SystemRoot\System32\sc.exe" stop $serviceName 2>&1
            $null = Wait-ServiceStopped -Seconds 45
        }
        $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -ne $existingService -and $existingService.Status -eq "Stopped") {
            $runtimePython = Join-Path $qualificationRoot "runtime\python.exe"
            if (Test-Path -LiteralPath $runtimePython -PathType Leaf) {
                $null = & $runtimePython `
                    -m causure.team_windows_service_cli remove 2>&1
            }
            if ($null -ne (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
                $null = & "$env:SystemRoot\System32\sc.exe" delete $serviceName 2>&1
            }
        }
    }
    $serviceAbsentAfterCleanup = Wait-ServiceAbsent -Seconds 15

    if (
        $rootCreated -and
        $serviceAbsentAfterCleanup -and
        -not $KeepArtifacts -and
        (Test-Path -LiteralPath $qualificationRoot)
    ) {
        $resolvedQualificationRoot = (Resolve-Path -LiteralPath $qualificationRoot).Path
        if (-not [string]::Equals(
                $resolvedQualificationRoot,
                $qualificationRoot,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw [InvalidOperationException]::new("refusing to remove an unexpected qualification path")
        }
        Remove-Item -LiteralPath $resolvedQualificationRoot -Recurse -Force
    }
    $rootRemovedAfterCleanup = -not (Test-Path -LiteralPath $qualificationRoot)

    if (-not $passed) {
        $evidence = [ordered]@{
            schema_version = "1.0"
            result = "failed"
            failed_stage = $stageBeforeCleanup
            failure_type = $failureType
        }
    }
    $evidence.started_at_utc = $startedAt.ToString("O")
    $evidence.finished_at_utc = [DateTimeOffset]::UtcNow.ToString("O")
    $evidence.cleanup = [ordered]@{
        service_absent = $serviceAbsentAfterCleanup
        qualification_root_removed = $rootRemovedAfterCleanup
    }
    [IO.File]::WriteAllText(
        [IO.Path]::GetFullPath($ReportPath),
        ($evidence | ConvertTo-Json -Depth 10),
        [Text.UTF8Encoding]::new($false)
    )
}

if (-not $passed -or -not $serviceAbsentAfterCleanup -or (-not $KeepArtifacts -and -not $rootRemovedAfterCleanup)) {
    exit 1
}

$evidence | ConvertTo-Json -Depth 10
