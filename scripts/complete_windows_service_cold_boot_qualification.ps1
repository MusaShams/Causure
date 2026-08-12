[CmdletBinding(DefaultParameterSetName = "Complete")]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "Complete")]
    [string]$StatePath,

    [Parameter(Mandatory = $true, ParameterSetName = "Complete")]
    [ValidatePattern("^[a-f0-9]{64}$")]
    [string]$StateSha256,

    [Parameter(Mandatory = $true, ParameterSetName = "Probe")]
    [string]$ProbePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$qualificationRoot = "C:\ProgramData\CausureColdBootQualification"
$reportRoot = "C:\ProgramData\CausureColdBootReport"
$fixedStatePath = Join-Path $qualificationRoot "qualification-state.json"
$fixedCompletionPath = Join-Path $qualificationRoot "complete.ps1"
$fixedProbePath = Join-Path $qualificationRoot "system-pwsh-probe.json"
$fixedReportPath = Join-Path $reportRoot "windows-service-cold-boot.json"
$taskName = "CausureColdBootQualification"
$serviceName = "CausureTeam"
$serviceDisplayName = "Causure Team Service"
$servicePrincipal = "NT SERVICE\CausureTeam"
$packageVersion = "0.4.0a15"
$runtimePath = "C:\Program Files\Causure\Team\$packageVersion"
$receiptPath = "C:\ProgramData\Causure\windows-service-installation.json"
$receiptBackupPath = (
    "C:\ProgramData\Causure\windows-service-installation.removal-backup.json"
)
$installedManifestPath = "C:\ProgramData\Causure\windows-service-bundle-manifest.json"
$firewallRuleName = "Causure-ColdBoot-Block-Service-Egress"

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IsSystem {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    return $identity.User.Value -eq "S-1-5-18"
}

function Write-AtomicJson {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [object]$Value
    )

    $resolved = [IO.Path]::GetFullPath($Path)
    $parent = Split-Path -Parent $resolved
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw [IO.DirectoryNotFoundException]::new("JSON output parent is unavailable")
    }
    $temporary = Join-Path $parent ("." + [Guid]::NewGuid().ToString("N") + ".tmp")
    try {
        [IO.File]::WriteAllText(
            $temporary,
            ($Value | ConvertTo-Json -Depth 12),
            [Text.UTF8Encoding]::new($false)
        )
        Move-Item -LiteralPath $temporary -Destination $resolved
    }
    finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}

function Assert-ExactProperties {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [string[]]$Names,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    if ($null -eq $Value) {
        throw [InvalidDataException]::new("$Label is missing")
    }
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $expected = @($Names | Sort-Object)
    if (@(Compare-Object -ReferenceObject $expected -DifferenceObject $actual).Count -ne 0) {
        throw [InvalidDataException]::new("$Label has unknown or missing fields")
    }
}

function Assert-UniqueJsonProperties {
    param(
        [Parameter(Mandatory = $true)]
        [Text.Json.JsonElement]$Element
    )

    if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Object) {
        $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $names.Add($property.Name)) {
                throw [InvalidDataException]::new("JSON contains a duplicate object field")
            }
            Assert-UniqueJsonProperties -Element $property.Value
        }
    }
    elseif ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Array) {
        foreach ($item in $Element.EnumerateArray()) {
            Assert-UniqueJsonProperties -Element $item
        }
    }
}

function ConvertFrom-ClosedJsonBytes {
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    try {
        $text = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
        $options = [Text.Json.JsonDocumentOptions]::new()
        $options.AllowTrailingCommas = $false
        $options.CommentHandling = [Text.Json.JsonCommentHandling]::Disallow
        $options.MaxDepth = 32
        $document = [Text.Json.JsonDocument]::Parse($text, $options)
        try {
            Assert-UniqueJsonProperties -Element $document.RootElement
        }
        finally {
            $document.Dispose()
        }
        return $text | ConvertFrom-Json -Depth 32
    }
    catch {
        throw [InvalidDataException]::new("$Label is not closed UTF-8 JSON")
    }
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
        $output = $standardOutputTask.GetAwaiter().GetResult().TrimEnd()
        $standardError = $standardErrorTask.GetAwaiter().GetResult().TrimEnd()
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
        throw [InvalidOperationException]::new("$Operation failed: $exitDescription")
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

function Start-ServiceWithoutWaiting {
    $controller = [ServiceProcess.ServiceController]::new($serviceName)
    try {
        $controller.Refresh()
        if ($controller.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) {
            throw [InvalidOperationException]::new(
                "the negative-test service is not stopped before its start request"
            )
        }
        $requestedAt = [DateTimeOffset]::UtcNow
        try {
            $controller.Start()
        }
        catch {
            throw [InvalidOperationException]::new(
                "the non-waiting SCM start request was not accepted"
            )
        }
    }
    finally {
        $controller.Dispose()
    }

    $processDeadline = [DateTimeOffset]::UtcNow.AddSeconds(15)
    do {
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'"
        $processId = [int]$service.ProcessId
        if ($processId -gt 0) {
            return [pscustomobject]@{
                requested_at_utc = $requestedAt
                process_id = $processId
            }
        }
        Start-Sleep -Milliseconds 25
    } while ([DateTimeOffset]::UtcNow -lt $processDeadline)

    throw [InvalidOperationException]::new(
        "the non-waiting SCM start did not expose a service process ID"
    )
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
    param([ValidateRange(1, 180)][int]$Seconds = 75)

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
    param(
        [Parameter(Mandatory = $true)]
        [int]$Port,

        [ValidateRange(1, 600)]
        [int]$Seconds = 90,

        [switch]$AutomaticStart
    )

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($Seconds)
    $runningAt = $null
    $runningPid = 0
    do {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -eq $service) {
            throw [InvalidOperationException]::new("service disappeared before readiness")
        }
        if ($service.Status -eq "Running") {
            if ($null -eq $runningAt) {
                $runningAt = [DateTimeOffset]::UtcNow
                $serviceCim = Get-CimInstance `
                    -ClassName Win32_Service `
                    -Filter "Name='$serviceName'"
                $runningPid = [int]$serviceCim.ProcessId
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
                    $readyAt = [DateTimeOffset]::UtcNow
                    return [ordered]@{
                        scm_running_at_utc = $runningAt.ToString("O")
                        ready_at_utc = $readyAt.ToString("O")
                        running_to_ready_seconds = [Math]::Round(
                            ($readyAt - $runningAt).TotalSeconds,
                            3
                        )
                        process_id = $runningPid
                        health_status = [int]$health.StatusCode
                        readiness_status = [int]$ready.StatusCode
                        automatic_start_observed = $AutomaticStart.IsPresent
                    }
                }
            }
            catch {
                # SCM running precedes synchronous Entra refresh and listener readiness.
            }
        }
        elseif ($null -ne $runningAt -and $service.Status -eq "Stopped") {
            throw [InvalidOperationException]::new("service stopped after SCM running but before readiness")
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw [TimeoutException]::new("service did not become healthy and ready")
}

function Assert-ProbesUnavailable {
    param([Parameter(Mandatory = $true)][int]$Port)

    $result = [ordered]@{}
    foreach ($probeName in @("healthz", "readyz")) {
        $unavailable = $false
        try {
            $response = Invoke-WebRequest `
                -Uri "http://127.0.0.1:$Port/$probeName" `
                -SkipHttpErrorCheck `
                -TimeoutSec 2
            $unavailable = $response.StatusCode -ne 200
        }
        catch {
            $unavailable = $true
        }
        if (-not $unavailable) {
            throw [InvalidOperationException]::new(
                "network-unavailable service still exposed a successful probe"
            )
        }
        $result[$probeName + "_unavailable"] = $true
    }
    return $result
}

function Find-ExactScmFailureEvent {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet(7031, 7034)]
        [int]$EventId,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 100)]
        [int]$FailureCount,

        [Parameter(Mandatory = $true)]
        [long]$AfterRecordId,

        [Parameter(Mandatory = $true)]
        [DateTimeOffset]$NotBefore,

        [int]$RestartDelayMilliseconds = -1,

        [int]$ActionCode = -1
    )

    $events = @(Get-WinEvent `
            -FilterHashtable @{
                LogName = "System"
                ProviderName = "Service Control Manager"
                Id = $EventId
                StartTime = $NotBefore.LocalDateTime
            } `
            -ErrorAction SilentlyContinue)
    foreach ($event in @($events | Sort-Object -Property RecordId)) {
        if ([long]$event.RecordId -le $AfterRecordId) {
            continue
        }
        $properties = @($event.Properties)
        if (
            $properties.Count -lt 2 -or
            [string]$properties[0].Value -ne $serviceDisplayName -or
            [int][string]$properties[1].Value -ne $FailureCount
        ) {
            continue
        }
        if (
            $RestartDelayMilliseconds -ge 0 -and
            (
                $properties.Count -lt 4 -or
                [int][string]$properties[2].Value -ne $RestartDelayMilliseconds -or
                [int][string]$properties[3].Value -ne $ActionCode
            )
        ) {
            continue
        }
        return $event
    }
    return $null
}

function Wait-ExactScmFailureEvent {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet(7031, 7034)]
        [int]$EventId,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 100)]
        [int]$FailureCount,

        [Parameter(Mandatory = $true)]
        [long]$AfterRecordId,

        [Parameter(Mandatory = $true)]
        [DateTimeOffset]$NotBefore,

        [ValidateRange(1, 300)]
        [int]$Seconds,

        [int]$RestartDelayMilliseconds = -1,

        [int]$ActionCode = -1
    )

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($Seconds)
    do {
        $event = Find-ExactScmFailureEvent `
            -EventId $EventId `
            -FailureCount $FailureCount `
            -AfterRecordId $AfterRecordId `
            -NotBefore $NotBefore `
            -RestartDelayMilliseconds $RestartDelayMilliseconds `
            -ActionCode $ActionCode
        if ($null -ne $event) {
            return $event
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    throw [TimeoutException]::new(
        "exact SCM failure event $EventId count $FailureCount was not observed"
    )
}

function Get-ExactRecoveryPolicy {
    $recovery = (Invoke-ServiceCli -Arguments @("recovery-status")) | ConvertFrom-Json
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
        throw [InvalidOperationException]::new("SCM recovery policy is not exact")
    }
    return $recovery
}

function Get-ExactServiceConfiguration {
    $python = Join-Path $runtimePath "python.exe"
    $code = (
        "import json,win32service as s; " +
        "m=s.OpenSCManager(None,None,s.SC_MANAGER_CONNECT); " +
        "h=s.OpenService(m,'CausureTeam',s.SERVICE_QUERY_CONFIG); " +
        "q=s.QueryServiceConfig(h); " +
        "d=s.QueryServiceConfig2(h,s.SERVICE_CONFIG_DELAYED_AUTO_START_INFO); " +
        "i=s.QueryServiceConfig2(h,s.SERVICE_CONFIG_SERVICE_SID_INFO); " +
        "print(json.dumps({'start_type':q[1],'automatic_constant':s.SERVICE_AUTO_START," +
        "'binary_path':q[3],'account':q[7],'delayed_automatic':bool(d)," +
        "'sid_type':i,'unrestricted_sid_constant':s.SERVICE_SID_TYPE_UNRESTRICTED})); " +
        "s.CloseServiceHandle(h); s.CloseServiceHandle(m)"
    )
    $configuration = (Invoke-CheckedNative `
        -Executable $python `
        -Arguments @("-I", "-B", "-c", $code) `
        -Operation "SCM service configuration query") | ConvertFrom-Json
    Assert-ExactProperties `
        -Value $configuration `
        -Names @(
            "start_type",
            "automatic_constant",
            "binary_path",
            "account",
            "delayed_automatic",
            "sid_type",
            "unrestricted_sid_constant"
        ) `
        -Label "SCM service configuration"
    $expectedExecutable = Join-Path $runtimePath "pythonservice.exe"
    $actualExecutable = ([string]$configuration.binary_path).Trim().Trim('"')
    if (
        $configuration.start_type -ne $configuration.automatic_constant -or
        $configuration.delayed_automatic -ne $true -or
        -not [string]::Equals(
            $actualExecutable,
            $expectedExecutable,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            [string]$configuration.account,
            $servicePrincipal,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        $configuration.sid_type -ne $configuration.unrestricted_sid_constant
    ) {
        throw [InvalidOperationException]::new("SCM service configuration is not exact")
    }
    return [ordered]@{
        start_type = "automatic"
        delayed_automatic = $true
        binary_path = $actualExecutable
        account = [string]$configuration.account
        unrestricted_service_sid = $true
    }
}

if ($PSCmdlet.ParameterSetName -eq "Probe") {
    if (
        -not [string]::Equals(
            [IO.Path]::GetFullPath($ProbePath),
            $fixedProbePath,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath($PSCommandPath),
            $fixedCompletionPath,
            [StringComparison]::OrdinalIgnoreCase
        )
    ) {
        throw [InvalidOperationException]::new("SYSTEM probe paths are not exact")
    }
    if (-not (Test-IsSystem) -or -not (Test-IsAdministrator)) {
        throw [UnauthorizedAccessException]::new("SYSTEM probe did not run as LocalSystem")
    }
    if (-not [Environment]::Is64BitProcess -or $PSVersionTable.PSVersion.Major -lt 7) {
        throw [PlatformNotSupportedException]::new("SYSTEM probe requires 64-bit PowerShell 7")
    }
    if (Test-Path -LiteralPath $fixedProbePath) {
        throw [InvalidOperationException]::new("SYSTEM probe output already exists")
    }
    $probe = [ordered]@{
        schema_version = "1.0"
        identity_sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        identity_name = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        is_64_bit_process = [Environment]::Is64BitProcess
        powershell_version = $PSVersionTable.PSVersion.ToString()
        completed_at_utc = [DateTimeOffset]::UtcNow.ToString("O")
    }
    Write-AtomicJson -Path $fixedProbePath -Value $probe
    $probe | ConvertTo-Json -Depth 5
    return
}

$startedAt = [DateTimeOffset]::UtcNow
$stage = "validate_execution"
$passed = $false
$failureType = $null
$failureMessage = $null
$state = $null
$operatorAclBaselines = @()
$firewallRuleCreated = $false
$trustWithheld = $false
$trustBackupPath = $null
$trustOriginalSha256 = $null
$bundleRemovalCompleted = $false
$serviceAbsentAfterCleanup = $false
$runtimeAbsentAfterCleanup = $false
$receiptAbsentAfterCleanup = $false
$receiptBackupAbsentAfterCleanup = $false
$installedManifestAbsentAfterCleanup = $false
$qualificationRootRemovedAfterCleanup = $false
$taskAbsentAfterCleanup = $false
$firewallRuleAbsentAfterCleanup = $false
$evidence = [ordered]@{}
$finalSucceeded = $false

try {
    if (-not (Test-IsSystem) -or -not (Test-IsAdministrator)) {
        throw [UnauthorizedAccessException]::new("cold-boot completion requires LocalSystem")
    }
    if (-not [Environment]::Is64BitProcess -or $PSVersionTable.PSVersion.Major -lt 7) {
        throw [PlatformNotSupportedException]::new("cold-boot completion requires 64-bit PowerShell 7")
    }
    if (
        -not [string]::Equals(
            [IO.Path]::GetFullPath($StatePath),
            $fixedStatePath,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath($PSCommandPath),
            $fixedCompletionPath,
            [StringComparison]::OrdinalIgnoreCase
        )
    ) {
        throw [InvalidOperationException]::new("completion paths are not exact")
    }
    if (-not (Test-Path -LiteralPath $fixedStatePath -PathType Leaf)) {
        throw [IO.FileNotFoundException]::new("protected qualification state is missing")
    }
    if (Test-Path -LiteralPath $fixedReportPath) {
        throw [InvalidOperationException]::new("cold-boot report already exists")
    }
    $stateBytes = [IO.File]::ReadAllBytes($fixedStatePath)
    if ($stateBytes.Length -lt 2 -or $stateBytes.Length -gt 128KB) {
        throw [InvalidDataException]::new("qualification state size is outside the supported limit")
    }
    $actualStateSha256 = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($stateBytes)
    ).ToLowerInvariant()
    if (-not [string]::Equals(
            $actualStateSha256,
            $StateSha256,
            [StringComparison]::Ordinal
        )) {
        throw [InvalidDataException]::new("qualification state digest does not match the task binding")
    }
    $state = ConvertFrom-ClosedJsonBytes -Bytes $stateBytes -Label "qualification state"
    Assert-ExactProperties `
        -Value $state `
        -Names @(
            "schema_version",
            "qualification_id",
            "prepared_at_utc",
            "prepared_boot_time_utc",
            "qualification_root",
            "report_path",
            "scheduled_task_name",
            "pwsh_path",
            "completion_script_path",
            "completion_script_sha256",
            "package_version",
            "service_name",
            "service_principal",
            "runtime_path",
            "receipt_path",
            "receipt_backup_path",
            "installed_manifest_path",
            "host_configuration_path",
            "host_configuration_sha256",
            "refresh_configuration_path",
            "refresh_configuration_sha256",
            "trust_store_path",
            "database_path",
            "port",
            "bundle_sha256",
            "manifest_sha256",
            "manifest_file_count",
            "operator_acl_baselines"
        ) `
        -Label "qualification state"
    if (
        $state.schema_version -ne "1.0" -or
        $state.package_version -ne $packageVersion -or
        $state.service_name -ne $serviceName -or
        $state.service_principal -ne $servicePrincipal -or
        $state.scheduled_task_name -ne $taskName -or
        $state.qualification_root -ne $qualificationRoot -or
        $state.report_path -ne $fixedReportPath -or
        $state.completion_script_path -ne $fixedCompletionPath -or
        $state.runtime_path -ne $runtimePath -or
        $state.receipt_path -ne $receiptPath -or
        $state.receipt_backup_path -ne $receiptBackupPath -or
        $state.installed_manifest_path -ne $installedManifestPath -or
        ($state.port -isnot [int] -and $state.port -isnot [long]) -or
        $state.port -lt 1024 -or
        $state.port -gt 65535 -or
        $state.bundle_sha256 -notmatch "^[a-f0-9]{64}$" -or
        $state.manifest_sha256 -notmatch "^[a-f0-9]{64}$" -or
        $state.host_configuration_sha256 -notmatch "^[a-f0-9]{64}$" -or
        $state.refresh_configuration_sha256 -notmatch "^[a-f0-9]{64}$" -or
        $state.completion_script_sha256 -notmatch "^[a-f0-9]{64}$" -or
        (
            $state.manifest_file_count -isnot [int] -and
            $state.manifest_file_count -isnot [long]
        ) -or
        $state.manifest_file_count -lt 1 -or
        $state.manifest_file_count -gt 20000
    ) {
        throw [InvalidDataException]::new("qualification state values are invalid")
    }
    $null = [Guid]::ParseExact([string]$state.qualification_id, "N")
    $preparedAt = [DateTimeOffset]::Parse(
        [string]$state.prepared_at_utc,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind
    )
    $preparedBootTime = [DateTimeOffset]::Parse(
        [string]$state.prepared_boot_time_utc,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind
    )
    $completionHash = (Get-FileHash `
        -LiteralPath $fixedCompletionPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($completionHash -ne $state.completion_script_sha256) {
        throw [InvalidDataException]::new("completion script digest changed after arming")
    }
    $currentPwsh = (Get-Process -Id $PID).Path
    if (-not [string]::Equals(
            $currentPwsh,
            [string]$state.pwsh_path,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw [InvalidOperationException]::new("startup task used an unexpected PowerShell host")
    }
    $expectedTaskArguments = (
        "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass " +
        "-File $fixedCompletionPath -StatePath $fixedStatePath " +
        "-StateSha256 $StateSha256"
    )
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
    if (
        @($task.Actions).Count -ne 1 -or
        -not [string]::Equals(
            [string]$task.Actions[0].Execute,
            [string]$state.pwsh_path,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        $task.Actions[0].Arguments -ne $expectedTaskArguments -or
        $task.Actions[0].WorkingDirectory -ne $reportRoot -or
        $task.Principal.UserId -notin @("SYSTEM", "S-1-5-18") -or
        @($task.Triggers).Count -ne 1 -or
        $task.Triggers[0].CimClass.CimClassName -ne "MSFT_TaskBootTrigger" -or
        $task.Triggers[0].Delay -ne "PT30S"
    ) {
        throw [InvalidOperationException]::new("startup task no longer matches the armed definition")
    }
    $operatorAclBaselines = @($state.operator_acl_baselines)
    $expectedAclPaths = @(
        [string]$state.host_configuration_path,
        (Split-Path -Parent ([string]$state.host_configuration_path)),
        [string]$state.refresh_configuration_path,
        (Split-Path -Parent ([string]$state.refresh_configuration_path)),
        (Split-Path -Parent ([string]$state.trust_store_path)),
        (Split-Path -Parent ([string]$state.database_path))
    ) | Select-Object -Unique
    if ($operatorAclBaselines.Count -ne $expectedAclPaths.Count) {
        throw [InvalidDataException]::new("operator ACL baseline set is incomplete")
    }
    $seenAclPaths = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($baseline in $operatorAclBaselines) {
        Assert-ExactProperties `
            -Value $baseline `
            -Names @("path", "access_sddl") `
            -Label "operator ACL baseline"
        if (
            $baseline.path -isnot [string] -or
            $baseline.access_sddl -isnot [string] -or
            $baseline.access_sddl.Length -lt 2 -or
            $baseline.access_sddl.Length -gt 16384 -or
            $baseline.path -notin $expectedAclPaths -or
            -not $seenAclPaths.Add($baseline.path)
        ) {
            throw [InvalidDataException]::new("operator ACL baseline is invalid")
        }
    }

    $stage = "verify_reboot"
    $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
    $currentBootTime = [DateTimeOffset]$operatingSystem.LastBootUpTime
    $currentBootTime = $currentBootTime.ToUniversalTime()
    if ($currentBootTime -le $preparedBootTime -or $currentBootTime -le $preparedAt) {
        throw [InvalidOperationException]::new("completion did not run after a new system boot")
    }

    $stage = "verify_installation"
    foreach ($requiredPath in @(
            $runtimePath,
            $receiptPath,
            $installedManifestPath,
            [string]$state.host_configuration_path,
            [string]$state.refresh_configuration_path
        )) {
        if (-not (Test-Path -LiteralPath $requiredPath)) {
            throw [IO.FileNotFoundException]::new("cold-boot installation input is missing")
        }
    }
    $receiptBytes = [IO.File]::ReadAllBytes($receiptPath)
    $receipt = ConvertFrom-ClosedJsonBytes -Bytes $receiptBytes -Label "installation receipt"
    Assert-ExactProperties `
        -Value $receipt `
        -Names @(
            "schema_version",
            "package_version",
            "service_name",
            "runtime_path",
            "manifest_path",
            "manifest_sha256",
            "host_configuration_path",
            "host_configuration_sha256",
            "host_configuration_byte_count",
            "automatic_start",
            "removal_started",
            "operator_acl_backups"
        ) `
        -Label "installation receipt"
    if (
        $receipt.package_version -ne $packageVersion -or
        $receipt.service_name -ne $serviceName -or
        $receipt.runtime_path -ne $runtimePath -or
        $receipt.manifest_path -ne $installedManifestPath -or
        $receipt.manifest_sha256 -ne $state.manifest_sha256 -or
        $receipt.host_configuration_path -ne $state.host_configuration_path -or
        $receipt.host_configuration_sha256 -ne $state.host_configuration_sha256 -or
        $receipt.automatic_start -ne $true -or
        $receipt.removal_started -ne $false
    ) {
        throw [InvalidDataException]::new("installation receipt does not bind the armed inputs")
    }
    if (
        (Get-FileHash -LiteralPath $installedManifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne
            $state.manifest_sha256 -or
        (Get-FileHash -LiteralPath $state.host_configuration_path -Algorithm SHA256).Hash.ToLowerInvariant() -ne
            $state.host_configuration_sha256 -or
        (Get-FileHash -LiteralPath $state.refresh_configuration_path -Algorithm SHA256).Hash.ToLowerInvariant() -ne
            $state.refresh_configuration_sha256
    ) {
        throw [InvalidDataException]::new("installed configuration or manifest bytes changed")
    }
    $serviceConfiguration = Get-ExactServiceConfiguration
    $recovery = Get-ExactRecoveryPolicy

    $stage = "automatic_start_readiness"
    $automaticReadiness = Wait-Ready `
        -Port $state.port `
        -Seconds 360 `
        -AutomaticStart
    $automaticProcess = Get-Process `
        -Id $automaticReadiness.process_id `
        -ErrorAction Stop
    $automaticProcessStartedAt = [DateTimeOffset]$automaticProcess.StartTime
    $automaticProcessStartedAt = $automaticProcessStartedAt.ToUniversalTime()
    if ($automaticProcessStartedAt -lt $currentBootTime) {
        throw [InvalidOperationException]::new("automatic service process predates the qualified boot")
    }

    $stage = "prepare_network_unavailable"
    $null = Invoke-ServiceCli -Arguments @("stop")
    if (-not (Wait-ServiceStopped -Seconds 75)) {
        throw [TimeoutException]::new("service did not stop before network isolation")
    }
    $trustPath = [string]$state.trust_store_path
    if (-not (Test-Path -LiteralPath $trustPath -PathType Leaf)) {
        throw [IO.FileNotFoundException]::new("initial automatic start did not publish trust")
    }
    $trustBackupPath = Join-Path (Split-Path -Parent $trustPath) "entra-trust.pre-network.json"
    if (Test-Path -LiteralPath $trustBackupPath) {
        throw [InvalidOperationException]::new("network-test trust backup already exists")
    }
    $trustOriginalSha256 = (Get-FileHash `
        -LiteralPath $trustPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    Move-Item -LiteralPath $trustPath -Destination $trustBackupPath
    $trustWithheld = $true
    if ($null -ne (Get-NetFirewallRule -Name $firewallRuleName -ErrorAction SilentlyContinue)) {
        throw [InvalidOperationException]::new("network-test firewall rule already exists")
    }
    $serviceExecutable = Join-Path $runtimePath "pythonservice.exe"
    $firewallRule = New-NetFirewallRule `
        -Name $firewallRuleName `
        -DisplayName $firewallRuleName `
        -Description "Temporary Causure cold-boot service-only egress block" `
        -Direction Outbound `
        -Action Block `
        -Program $serviceExecutable `
        -Profile Any `
        -Enabled True `
        -PolicyStore PersistentStore
    $firewallRuleCreated = $true
    $applicationFilter = Get-NetFirewallApplicationFilter `
        -AssociatedNetFirewallRule $firewallRule
    if (
        $firewallRule.Direction -ne "Outbound" -or
        $firewallRule.Action -ne "Block" -or
        $firewallRule.Enabled -ne "True" -or
        -not [string]::Equals(
            [string]$applicationFilter.Program,
            $serviceExecutable,
            [StringComparison]::OrdinalIgnoreCase
        )
    ) {
        throw [InvalidOperationException]::new("network-test firewall rule is not exact")
    }

    $stage = "non_crash_recovery"
    $systemEventBaseline = Get-WinEvent -LogName "System" -MaxEvents 1
    $systemEventBaselineRecordId = [long]$systemEventBaseline.RecordId
    $firstFailureStart = Start-ServiceWithoutWaiting
    $failureStartedAt = [DateTimeOffset]$firstFailureStart.requested_at_utc
    $firstFailurePid = [int]$firstFailureStart.process_id
    if (-not (Wait-ServiceStopped -Seconds 75)) {
        throw [TimeoutException]::new("network-unavailable start did not fail closed")
    }
    $firstFailureStoppedObservedAt = [DateTimeOffset]::UtcNow
    $firstFailureEvent = Wait-ExactScmFailureEvent `
        -EventId 7031 `
        -FailureCount 1 `
        -AfterRecordId $systemEventBaselineRecordId `
        -NotBefore $failureStartedAt.AddSeconds(-1) `
        -Seconds 15 `
        -RestartDelayMilliseconds 120000 `
        -ActionCode 1
    $firstFailureEventAt = ([DateTimeOffset]$firstFailureEvent.TimeCreated).ToUniversalTime()
    $firstFailureProbes = Assert-ProbesUnavailable -Port $state.port
    $recoveryDeadline = $firstFailureEventAt.AddSeconds(220)
    $recoveredPid = $null
    $recoveredAt = $null
    $secondFailureEvent = $null
    do {
        $recoveredCim = Get-CimInstance `
            -ClassName Win32_Service `
            -Filter "Name='$serviceName'" `
            -ErrorAction SilentlyContinue
        if (
            $null -eq $recoveredPid -and
            $null -ne $recoveredCim -and
            [int]$recoveredCim.ProcessId -gt 0
        ) {
            $recoveredPid = [int]$recoveredCim.ProcessId
            $recoveredAt = [DateTimeOffset]::UtcNow
        }
        $secondFailureEvent = Find-ExactScmFailureEvent `
            -EventId 7034 `
            -FailureCount 2 `
            -AfterRecordId ([long]$firstFailureEvent.RecordId) `
            -NotBefore $firstFailureEventAt
        if ($null -ne $secondFailureEvent) {
            break
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTimeOffset]::UtcNow -lt $recoveryDeadline)
    if ($null -eq $secondFailureEvent) {
        throw [TimeoutException]::new(
            "post-boot second SCM failure event was not observed after recovery"
        )
    }
    $secondFailureEventAt = ([DateTimeOffset]$secondFailureEvent.TimeCreated).ToUniversalTime()
    $nonCrashRecoverySeconds = ($secondFailureEventAt - $firstFailureEventAt).TotalSeconds
    if ($nonCrashRecoverySeconds -lt 110 -or $nonCrashRecoverySeconds -gt 210) {
        throw [InvalidOperationException]::new(
            "SCM failure events did not prove the bounded non-crash restart"
        )
    }
    if (-not (Wait-ServiceStopped -Seconds 15)) {
        throw [TimeoutException]::new("service was not stopped after its second SCM failure")
    }
    $secondFailureStoppedObservedAt = [DateTimeOffset]::UtcNow
    $secondFailureProbes = Assert-ProbesUnavailable -Port $state.port
    Start-Sleep -Seconds 10
    if ((Get-Service -Name $serviceName).Status -ne "Stopped") {
        throw [InvalidOperationException]::new("network-unavailable failures entered a restart loop")
    }
    $thirdFailureWithAction = Find-ExactScmFailureEvent `
        -EventId 7031 `
        -FailureCount 3 `
        -AfterRecordId ([long]$secondFailureEvent.RecordId) `
        -NotBefore $secondFailureEventAt
    $thirdFailureWithoutAction = Find-ExactScmFailureEvent `
        -EventId 7034 `
        -FailureCount 3 `
        -AfterRecordId ([long]$secondFailureEvent.RecordId) `
        -NotBefore $secondFailureEventAt
    if ($null -ne $thirdFailureWithAction -or $null -ne $thirdFailureWithoutAction) {
        throw [InvalidOperationException]::new(
            "network-unavailable failures produced a third SCM failure event"
        )
    }
    $postFailureRecovery = Get-ExactRecoveryPolicy

    $stage = "restore_network_and_readiness"
    Remove-NetFirewallRule -Name $firewallRuleName
    $firewallRuleCreated = $false
    if ($null -ne (Get-NetFirewallRule -Name $firewallRuleName -ErrorAction SilentlyContinue)) {
        throw [InvalidOperationException]::new("network-test firewall rule remained after removal")
    }
    Move-Item -LiteralPath $trustBackupPath -Destination $trustPath
    $trustWithheld = $false
    if (
        (Get-FileHash -LiteralPath $trustPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne
            $trustOriginalSha256
    ) {
        throw [InvalidDataException]::new("last-known-good trust was not restored exactly")
    }
    $restoredRecovery = (Invoke-ServiceCli -Arguments @("recovery-set")) | ConvertFrom-Json
    $null = Get-ExactRecoveryPolicy
    $null = Invoke-ServiceCli -Arguments @("start")
    $restoredReadiness = Wait-Ready -Port $state.port -Seconds 90

    $stage = "remove_running_bundle"
    $removerPath = Join-Path $runtimePath "management\remove.ps1"
    $removeInvocation = Invoke-NativeCapture `
        -Executable ([string]$state.pwsh_path) `
        -Arguments @("-NoLogo", "-NoProfile", "-NonInteractive", "-File", $removerPath)
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
    $operatorPathsPreserved = $true
    $operatorAclsRestored = $true
    foreach ($baseline in $operatorAclBaselines) {
        if (-not (Test-Path -LiteralPath $baseline.path)) {
            $operatorPathsPreserved = $false
            $operatorAclsRestored = $false
            break
        }
        $currentAcl = Get-Acl -LiteralPath $baseline.path
        $currentSddl = $currentAcl.GetSecurityDescriptorSddlForm(
            [Security.AccessControl.AccessControlSections]::Access
        )
        if ($currentSddl -ne $baseline.access_sddl) {
            $operatorAclsRestored = $false
            break
        }
    }
    if (-not $operatorPathsPreserved -or -not $operatorAclsRestored) {
        throw [InvalidOperationException]::new("bundle removal did not preserve operator state")
    }

    $evidence = [ordered]@{
        schema_version = "1.0"
        result = "passed"
        qualification_id = [string]$state.qualification_id
        os = [ordered]@{
            caption = $operatingSystem.Caption
            version = [Environment]::OSVersion.Version.ToString()
            build = [Environment]::OSVersion.Version.Build
            prepared_boot_time_utc = $preparedBootTime.ToUniversalTime().ToString("O")
            qualified_boot_time_utc = $currentBootTime.ToString("O")
            reboot_observed = $true
        }
        bundle = [ordered]@{
            package_version = $packageVersion
            bundle_sha256 = [string]$state.bundle_sha256
            manifest_sha256 = [string]$state.manifest_sha256
            manifest_file_count = [int]$state.manifest_file_count
        }
        startup_task = [ordered]@{
            one_shot = $true
            principal = "NT AUTHORITY\SYSTEM"
            powershell_path = [string]$state.pwsh_path
            completion_script_sha256 = [string]$state.completion_script_sha256
            state_sha256 = $StateSha256
            startup_delay_seconds = 30
        }
        installation = [ordered]@{
            automatic_start_receipt = $true
            start_type = $serviceConfiguration.start_type
            delayed_automatic = $serviceConfiguration.delayed_automatic
            service_account = $serviceConfiguration.account
            unrestricted_service_sid = $serviceConfiguration.unrestricted_service_sid
            exact_image_path = $serviceConfiguration.binary_path
            exact_recovery_policy = $true
            post_boot_non_crash_failure_flag = $recovery.apply_on_non_crash_failures
        }
        cold_boot = [ordered]@{
            performed = $true
            automatic_process_id = $automaticReadiness.process_id
            automatic_process_started_at_utc = $automaticProcessStartedAt.ToString("O")
            scm_running_at_utc = $automaticReadiness.scm_running_at_utc
            ready_at_utc = $automaticReadiness.ready_at_utc
            scm_running_to_ready_seconds = $automaticReadiness.running_to_ready_seconds
            health_status = $automaticReadiness.health_status
            readiness_status = $automaticReadiness.readiness_status
            readiness_gated_separately_from_scm = $true
        }
        network_unavailable = [ordered]@{
            method = "outbound block scoped to exact service executable with local trust withheld"
            start_request_method = "non_waiting_scm"
            recovery_observation_method = "structured_scm_failure_events"
            workstation_adapter_changed = $false
            global_firewall_policy_changed = $false
            first_process_id = $firstFailurePid
            first_start_at_utc = $failureStartedAt.ToString("O")
            first_stopped_observed_at_utc = $firstFailureStoppedObservedAt.ToString("O")
            first_failure_event_id = [int]$firstFailureEvent.Id
            first_failure_event_record_id = [long]$firstFailureEvent.RecordId
            first_failure_event_at_utc = $firstFailureEventAt.ToString("O")
            first_failure_restart_delay_milliseconds = 120000
            first_failure_action_code = 1
            recovery_process_id = $recoveredPid
            recovery_process_observed_at_utc = $(
                if ($null -ne $recoveredAt) { $recoveredAt.ToString("O") } else { $null }
            )
            expected_recovery_at_utc = $firstFailureEventAt.AddMilliseconds(120000).ToString("O")
            second_failure_event_id = [int]$secondFailureEvent.Id
            second_failure_event_record_id = [long]$secondFailureEvent.RecordId
            second_failure_event_at_utc = $secondFailureEventAt.ToString("O")
            second_failure_count = 2
            recovery_elapsed_seconds = [Math]::Round($nonCrashRecoverySeconds, 3)
            second_stopped_observed_at_utc = $secondFailureStoppedObservedAt.ToString("O")
            first_failure_restarted = $true
            second_failure_stopped_without_loop = $true
            first_failure_health_unavailable = $firstFailureProbes.healthz_unavailable
            first_failure_readiness_unavailable = $firstFailureProbes.readyz_unavailable
            second_failure_health_unavailable = $secondFailureProbes.healthz_unavailable
            second_failure_readiness_unavailable = $secondFailureProbes.readyz_unavailable
            non_crash_policy_effective_after_boot = $true
            exact_recovery_policy_remained = (
                $postFailureRecovery.apply_on_non_crash_failures -eq $true
            )
            last_known_good_restored_exactly = $true
            firewall_rule_removed = $true
        }
        restoration = [ordered]@{
            recovery_policy_reapplied = ($restoredRecovery.apply_on_non_crash_failures -eq $true)
            health_status = $restoredReadiness.health_status
            readiness_status = $restoredReadiness.readiness_status
        }
        removal = [ordered]@{
            running_service_removed = $true
            service_absent = $true
            runtime_absent = $true
            receipt_absent = $true
            receipt_backup_absent = $true
            installed_manifest_absent = $true
            operator_paths_preserved = $operatorPathsPreserved
            operator_acls_restored = $operatorAclsRestored
        }
    }
    $passed = $true
}
catch {
    $failureType = $_.Exception.GetType().Name
    $failureMessage = $_.Exception.Message
}
finally {
    $stageBeforeCleanup = $stage
    $stage = "cleanup"
    $cleanupErrors = [Collections.Generic.List[string]]::new()

    try {
        if ($null -ne (Get-NetFirewallRule -Name $firewallRuleName -ErrorAction SilentlyContinue)) {
            Remove-NetFirewallRule -Name $firewallRuleName
        }
    }
    catch {
        $cleanupErrors.Add("firewall rule cleanup failed")
    }
    $firewallRuleAbsentAfterCleanup = (
        $null -eq (Get-NetFirewallRule -Name $firewallRuleName -ErrorAction SilentlyContinue)
    )

    if ($trustWithheld -and -not [string]::IsNullOrWhiteSpace($trustBackupPath)) {
        try {
            $trustPathForCleanup = if ($null -ne $state) {
                [string]$state.trust_store_path
            }
            else {
                $null
            }
            if (
                -not [string]::IsNullOrWhiteSpace($trustPathForCleanup) -and
                (Test-Path -LiteralPath $trustBackupPath -PathType Leaf) -and
                -not (Test-Path -LiteralPath $trustPathForCleanup)
            ) {
                Move-Item -LiteralPath $trustBackupPath -Destination $trustPathForCleanup
                $trustWithheld = $false
            }
        }
        catch {
            $cleanupErrors.Add("last-known-good trust cleanup failed")
        }
    }

    try {
        $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        $runtimePython = Join-Path $runtimePath "python.exe"
        if (
            $null -ne $existingService -and
            $existingService.Status -ne "Stopped" -and
            (Test-Path -LiteralPath $runtimePython -PathType Leaf)
        ) {
            $stopInvocation = Invoke-NativeCapture `
                -Executable $runtimePython `
                -Arguments @(
                    "-I",
                    "-B",
                    "-m",
                    "causure.team_windows_service_cli",
                    "stop"
                )
            if ($stopInvocation.exit_code -ne 0 -and -not (Wait-ServiceStopped -Seconds 75)) {
                $cleanupErrors.Add("service CLI stop failed")
            }
        }
        $removerPath = Join-Path $runtimePath "management\remove.ps1"
        if (
            -not $bundleRemovalCompleted -and
            (Test-Path -LiteralPath $removerPath -PathType Leaf) -and
            (Test-Path -LiteralPath $receiptPath -PathType Leaf)
        ) {
            $cleanupPwsh = if ($null -ne $state) {
                [string]$state.pwsh_path
            }
            else {
                (Get-Process -Id $PID).Path
            }
            $removeInvocation = Invoke-NativeCapture `
                -Executable $cleanupPwsh `
                -Arguments @("-NoLogo", "-NoProfile", "-NonInteractive", "-File", $removerPath)
            if ($removeInvocation.exit_code -eq 0) {
                $bundleRemovalCompleted = $true
            }
            else {
                $cleanupErrors.Add("bundle remover cleanup failed")
            }
        }
    }
    catch {
        $cleanupErrors.Add("managed bundle cleanup failed")
    }

    try {
        $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        $runtimePython = Join-Path $runtimePath "python.exe"
        if ($null -ne $existingService -and $existingService.Status -ne "Stopped") {
            $null = & "$env:SystemRoot\System32\sc.exe" stop $serviceName 2>&1
            $null = Wait-ServiceStopped -Seconds 75
        }
        $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if (
            $null -ne $existingService -and
            $existingService.Status -eq "Stopped" -and
            (Test-Path -LiteralPath $runtimePython -PathType Leaf)
        ) {
            $removeInvocation = Invoke-NativeCapture `
                -Executable $runtimePython `
                -Arguments @(
                    "-I",
                    "-B",
                    "-m",
                    "causure.team_windows_service_cli",
                    "remove"
                )
            if ($removeInvocation.exit_code -ne 0) {
                $cleanupErrors.Add("service adapter cleanup failed")
            }
        }
        if ($null -ne (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
            $null = & "$env:SystemRoot\System32\sc.exe" delete $serviceName 2>&1
        }
        $serviceAbsentAfterCleanup = Wait-ServiceAbsent -Seconds 20
    }
    catch {
        $cleanupErrors.Add("service registration cleanup failed")
    }

    if ($operatorAclBaselines.Count -ne 0) {
        foreach ($baseline in $operatorAclBaselines) {
            try {
                if (Test-Path -LiteralPath $baseline.path) {
                    $acl = Get-Acl -LiteralPath $baseline.path
                    $acl.SetSecurityDescriptorSddlForm(
                        [string]$baseline.access_sddl,
                        [Security.AccessControl.AccessControlSections]::Access
                    )
                    Set-Acl -LiteralPath $baseline.path -AclObject $acl
                }
            }
            catch {
                $cleanupErrors.Add("operator ACL cleanup failed")
            }
        }
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
                    if ($managedPath -eq $runtimePath) {
                        $resolvedRuntime = (Resolve-Path -LiteralPath $managedPath).Path
                        if (-not [string]::Equals(
                                $resolvedRuntime,
                                $runtimePath,
                                [StringComparison]::OrdinalIgnoreCase
                            )) {
                            throw [InvalidOperationException]::new("runtime cleanup path is unexpected")
                        }
                        Remove-Item -LiteralPath $resolvedRuntime -Recurse -Force
                    }
                    else {
                        Remove-Item -LiteralPath $managedPath -Force
                    }
                }
                catch {
                    $cleanupErrors.Add("managed path cleanup failed")
                }
            }
        }
    }

    $runtimeAbsentAfterCleanup = -not (Test-Path -LiteralPath $runtimePath)
    $receiptAbsentAfterCleanup = -not (Test-Path -LiteralPath $receiptPath)
    $receiptBackupAbsentAfterCleanup = -not (Test-Path -LiteralPath $receiptBackupPath)
    $installedManifestAbsentAfterCleanup = -not (Test-Path -LiteralPath $installedManifestPath)

    try {
        if ($null -ne (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        }
    }
    catch {
        $cleanupErrors.Add("startup task cleanup failed")
    }
    $taskAbsentAfterCleanup = (
        $null -eq (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)
    )

    if (
        $serviceAbsentAfterCleanup -and
        $runtimeAbsentAfterCleanup -and
        (Test-Path -LiteralPath $qualificationRoot)
    ) {
        try {
            [Environment]::CurrentDirectory = $reportRoot
            Set-Location -LiteralPath $reportRoot
            $resolvedRoot = (Resolve-Path -LiteralPath $qualificationRoot).Path
            if (-not [string]::Equals(
                    $resolvedRoot,
                    $qualificationRoot,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                throw [InvalidOperationException]::new("qualification cleanup path is unexpected")
            }
            Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
        }
        catch {
            $cleanupErrors.Add("qualification root cleanup failed")
        }
    }
    $qualificationRootRemovedAfterCleanup = -not (Test-Path -LiteralPath $qualificationRoot)

    $finalSucceeded = (
        $passed -and
        $serviceAbsentAfterCleanup -and
        $runtimeAbsentAfterCleanup -and
        $receiptAbsentAfterCleanup -and
        $receiptBackupAbsentAfterCleanup -and
        $installedManifestAbsentAfterCleanup -and
        $qualificationRootRemovedAfterCleanup -and
        $taskAbsentAfterCleanup -and
        $firewallRuleAbsentAfterCleanup -and
        $cleanupErrors.Count -eq 0
    )
    if (-not $passed) {
        $evidence = [ordered]@{
            schema_version = "1.0"
            result = "failed"
            qualification_id = $(if ($null -ne $state) { [string]$state.qualification_id } else { $null })
            failed_stage = $stageBeforeCleanup
            failure_type = $failureType
            failure_message = $failureMessage
        }
    }
    elseif (-not $finalSucceeded) {
        $evidence.result = "failed"
        $evidence.failed_stage = "cleanup"
        $evidence.failure_type = "InvalidOperationException"
        $evidence.failure_message = "cold-boot qualification cleanup was incomplete"
    }
    $evidence.started_at_utc = $startedAt.ToString("O")
    $evidence.finished_at_utc = [DateTimeOffset]::UtcNow.ToString("O")
    $evidence.cleanup = [ordered]@{
        service_absent = $serviceAbsentAfterCleanup
        runtime_absent = $runtimeAbsentAfterCleanup
        receipt_absent = $receiptAbsentAfterCleanup
        receipt_backup_absent = $receiptBackupAbsentAfterCleanup
        installed_manifest_absent = $installedManifestAbsentAfterCleanup
        qualification_root_removed = $qualificationRootRemovedAfterCleanup
        startup_task_absent = $taskAbsentAfterCleanup
        firewall_rule_absent = $firewallRuleAbsentAfterCleanup
        errors = @($cleanupErrors)
    }
    Write-AtomicJson -Path $fixedReportPath -Value $evidence
}

if (-not $finalSucceeded) {
    exit 1
}

$evidence | ConvertTo-Json -Depth 12
