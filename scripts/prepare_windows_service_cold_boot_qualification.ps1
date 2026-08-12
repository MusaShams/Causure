[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BundlePath,

    [ValidateRange(1024, 65535)]
    [int]$Port = 18082
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$qualificationRoot = "C:\ProgramData\CausureColdBootQualification"
$reportRoot = "C:\ProgramData\CausureColdBootReport"
$statePath = Join-Path $qualificationRoot "qualification-state.json"
$completionSourcePath = Join-Path $PSScriptRoot "complete_windows_service_cold_boot_qualification.ps1"
$completionPath = Join-Path $qualificationRoot "complete.ps1"
$probePath = Join-Path $qualificationRoot "system-pwsh-probe.json"
$reportPath = Join-Path $reportRoot "windows-service-cold-boot.json"
$taskName = "CausureColdBootQualification"
$probeTaskName = "CausureColdBootQualification-SystemProbe"
$serviceName = "CausureTeam"
$servicePrincipal = "NT SERVICE\CausureTeam"
$packageVersion = "0.4.0a15"
$runtimePath = "C:\Program Files\Causure\Team\$packageVersion"
$receiptPath = "C:\ProgramData\Causure\windows-service-installation.json"
$receiptBackupPath = (
    "C:\ProgramData\Causure\windows-service-installation.removal-backup.json"
)
$installedManifestPath = "C:\ProgramData\Causure\windows-service-bundle-manifest.json"
$firewallRuleName = "Causure-ColdBoot-Block-Service-Egress"
$expectedBundleSha256 = "16ee1b521d70fa0670e1c2099843bc8a2ae22dd9520772748d6345ec1b6daf04"
$expectedManifestSha256 = "2a625fb8af7e7b0ef1bed119fab055772c5870660c40234c29fe342747b41eab"
$expectedManifestFileCount = 3318
$publicTenantId = "72f988bf-86f1-41af-91ab-2d7cd011db47"

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
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

function Protect-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)

    $null = Invoke-CheckedNative `
        -Executable "$env:SystemRoot\System32\icacls.exe" `
        -Arguments @(
            $Path,
            "/inheritance:r",
            "/grant:r",
            "NT AUTHORITY\SYSTEM:(OI)(CI)(F)",
            "BUILTIN\Administrators:(OI)(CI)(F)",
            "/Q"
        ) `
        -Operation "qualification directory ACL protection"
}

function Protect-File {
    param([Parameter(Mandatory = $true)][string]$Path)

    $null = Invoke-CheckedNative `
        -Executable "$env:SystemRoot\System32\icacls.exe" `
        -Arguments @(
            $Path,
            "/inheritance:r",
            "/grant:r",
            "NT AUTHORITY\SYSTEM:(F)",
            "BUILTIN\Administrators:(F)",
            "/Q"
        ) `
        -Operation "qualification file ACL protection"
}

function Invoke-ServiceCli {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

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

function New-SystemPrincipal {
    return New-ScheduledTaskPrincipal `
        -UserId "SYSTEM" `
        -LogonType ServiceAccount `
        -RunLevel Highest
}

function New-QualificationTaskSettings {
    return New-ScheduledTaskSettingsSet `
        -Compatibility Win8 `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 20) `
        -MultipleInstances IgnoreNew
}

function Assert-ExactRecoveryPolicy {
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

$stage = "preflight"
$armed = $false
$rootCreated = $false
$reportRootCreated = $false
$bundleInstalled = $false
$probeTaskRegistered = $false
$startupTaskRegistered = $false
$originalError = $null
$cleanupErrors = [Collections.Generic.List[string]]::new()
$result = $null

try {
    if (-not (Test-IsAdministrator)) {
        throw [UnauthorizedAccessException]::new("cold-boot preparation requires elevation")
    }
    if (-not [Environment]::Is64BitProcess -or $PSVersionTable.PSVersion.Major -lt 7) {
        throw [PlatformNotSupportedException]::new("cold-boot preparation requires 64-bit PowerShell 7")
    }
    if (-not (Test-Path -LiteralPath $completionSourcePath -PathType Leaf)) {
        throw [IO.FileNotFoundException]::new("cold-boot completion script is missing")
    }
    foreach ($fixedPath in @(
            $qualificationRoot,
            $reportRoot,
            $runtimePath,
            $receiptPath,
            $receiptBackupPath,
            $installedManifestPath
        )) {
        if (Test-Path -LiteralPath $fixedPath) {
            throw [InvalidOperationException]::new("a fixed cold-boot qualification target already exists")
        }
    }
    foreach ($fixedTask in @($taskName, $probeTaskName)) {
        if ($null -ne (Get-ScheduledTask -TaskName $fixedTask -ErrorAction SilentlyContinue)) {
            throw [InvalidOperationException]::new("a fixed cold-boot qualification task already exists")
        }
    }
    if ($null -ne (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
        throw [InvalidOperationException]::new("the fixed Windows service already exists")
    }
    if ($null -ne (Get-NetFirewallRule -Name $firewallRuleName -ErrorAction SilentlyContinue)) {
        throw [InvalidOperationException]::new("the fixed network-test firewall rule already exists")
    }
    if ($null -ne (Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue)) {
        throw [InvalidOperationException]::new("the qualification port is already in use")
    }

    $resolvedBundle = (Resolve-Path -LiteralPath $BundlePath).Path
    if ([IO.Path]::GetExtension($resolvedBundle) -ne ".zip") {
        throw [InvalidDataException]::new("qualification bundle must be a ZIP file")
    }
    $bundleItem = Get-Item -LiteralPath $resolvedBundle -Force
    if ($bundleItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw [IO.IOException]::new("qualification bundle cannot be a reparse point")
    }
    $bundleHash = (Get-FileHash `
        -LiteralPath $resolvedBundle `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($bundleHash -ne $expectedBundleSha256) {
        throw [InvalidDataException]::new("qualification bundle is not the exact a15 candidate")
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

    $stage = "create_protected_roots"
    $null = New-Item -ItemType Directory -Path $qualificationRoot
    $rootCreated = $true
    Protect-Directory -Path $qualificationRoot
    $null = New-Item -ItemType Directory -Path $reportRoot
    $reportRootCreated = $true
    Protect-Directory -Path $reportRoot
    $bundleRoot = Join-Path $qualificationRoot "bundle"
    $configRoot = Join-Path $qualificationRoot "config"
    $stateRoot = Join-Path $qualificationRoot "state"
    $dataRoot = Join-Path $qualificationRoot "data"
    $null = New-Item -ItemType Directory -Path $bundleRoot, $configRoot, $stateRoot, $dataRoot
    Copy-Item -LiteralPath $completionSourcePath -Destination $completionPath
    Protect-File -Path $completionPath
    $completionHash = (Get-FileHash `
        -LiteralPath $completionPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()

    $stage = "system_powershell_probe"
    $pwshPath = (Get-Command pwsh.exe -ErrorAction Stop).Source
    if (-not (Test-Path -LiteralPath $pwshPath -PathType Leaf)) {
        throw [IO.FileNotFoundException]::new("PowerShell 7 executable is unavailable")
    }
    $probeArguments = (
        "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass " +
        "-File $completionPath -ProbePath $probePath"
    )
    $probeAction = New-ScheduledTaskAction `
        -Execute $pwshPath `
        -Argument $probeArguments `
        -WorkingDirectory $qualificationRoot
    $probeTrigger = New-ScheduledTaskTrigger -Once -At ([DateTime]::Now.AddHours(1))
    $probePrincipal = New-SystemPrincipal
    $probeSettings = New-QualificationTaskSettings
    $null = Register-ScheduledTask `
        -TaskName $probeTaskName `
        -Action $probeAction `
        -Trigger $probeTrigger `
        -Principal $probePrincipal `
        -Settings $probeSettings `
        -Description "Disposable Causure LocalSystem PowerShell probe"
    $probeTaskRegistered = $true
    Start-ScheduledTask -TaskName $probeTaskName
    $probeDeadline = [DateTimeOffset]::UtcNow.AddSeconds(45)
    do {
        $probeTask = Get-ScheduledTask -TaskName $probeTaskName
        if (
            (Test-Path -LiteralPath $probePath -PathType Leaf) -and
            $probeTask.State -ne "Running"
        ) {
            break
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTimeOffset]::UtcNow -lt $probeDeadline)
    if (-not (Test-Path -LiteralPath $probePath -PathType Leaf)) {
        throw [TimeoutException]::new("LocalSystem PowerShell probe did not complete")
    }
    $probeInfo = Get-ScheduledTaskInfo -TaskName $probeTaskName
    if ($probeInfo.LastTaskResult -ne 0) {
        throw [InvalidOperationException]::new("LocalSystem PowerShell probe returned failure")
    }
    $probeBytes = [IO.File]::ReadAllBytes($probePath)
    $probe = ConvertFrom-ClosedJsonBytes -Bytes $probeBytes -Label "LocalSystem probe"
    Assert-ExactProperties `
        -Value $probe `
        -Names @(
            "schema_version",
            "identity_sid",
            "identity_name",
            "is_64_bit_process",
            "powershell_version",
            "completed_at_utc"
        ) `
        -Label "LocalSystem probe"
    if (
        $probe.schema_version -ne "1.0" -or
        $probe.identity_sid -ne "S-1-5-18" -or
        $probe.is_64_bit_process -ne $true -or
        ([Version]$probe.powershell_version).Major -lt 7
    ) {
        throw [InvalidOperationException]::new("LocalSystem PowerShell probe was not exact")
    }
    Unregister-ScheduledTask -TaskName $probeTaskName -Confirm:$false
    $probeTaskRegistered = $false
    Remove-Item -LiteralPath $probePath -Force

    $stage = "extract_and_configure"
    Expand-Archive -LiteralPath $resolvedBundle -DestinationPath $bundleRoot
    $manifestPath = Join-Path $bundleRoot "bundle-manifest.json"
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw [IO.FileNotFoundException]::new("bundle manifest is missing")
    }
    $manifestHash = (Get-FileHash `
        -LiteralPath $manifestPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($manifestHash -ne $expectedManifestSha256) {
        throw [InvalidDataException]::new("bundle manifest is not the exact a15 candidate")
    }
    $manifestBytes = [IO.File]::ReadAllBytes($manifestPath)
    $manifest = ConvertFrom-ClosedJsonBytes -Bytes $manifestBytes -Label "bundle manifest"
    Assert-ExactProperties `
        -Value $manifest `
        -Names @(
            "schema_version",
            "product",
            "package_version",
            "service_name",
            "build",
            "runtime",
            "install",
            "files"
        ) `
        -Label "bundle manifest"
    if (
        $manifest.schema_version -ne "1.0" -or
        $manifest.product -ne "Causure Windows Team Service Bundle" -or
        $manifest.package_version -ne $packageVersion -or
        $manifest.service_name -ne $serviceName -or
        @($manifest.files).Count -ne $expectedManifestFileCount
    ) {
        throw [InvalidDataException]::new("bundle manifest release contract is not exact")
    }

    $issuer = "https://login.microsoftonline.com/$publicTenantId/v2.0"
    $jwksUri = "https://login.microsoftonline.com/$publicTenantId/discovery/v2.0/keys"
    $refreshPath = Join-Path $configRoot "entra-refresh.json"
    $hostPath = Join-Path $configRoot "team-host.json"
    $trustPath = Join-Path $stateRoot "entra-trust.json"
    $databasePath = Join-Path $dataRoot "team.sqlite3"
    $refreshDocument = [ordered]@{
        schema_version = "1.0"
        store_id = "entra-cold-boot-qualification"
        snapshot_ttl_seconds = 3600
        tenants = @(
            [ordered]@{
                entra_tenant_id = $publicTenantId
                team_tenant_id = "tenant-cold-boot-qualification"
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
            path = $databasePath
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
            trust_store_path = $trustPath
            store_id = "entra-cold-boot-qualification"
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

    $operatorAclPaths = @(
        $hostPath,
        $configRoot,
        $refreshPath,
        $stateRoot,
        $dataRoot
    ) | Select-Object -Unique
    $operatorAclBaselines = @()
    foreach ($operatorAclPath in $operatorAclPaths) {
        $acl = Get-Acl -LiteralPath $operatorAclPath
        $operatorAclBaselines += [ordered]@{
            path = $operatorAclPath
            access_sddl = $acl.GetSecurityDescriptorSddlForm(
                [Security.AccessControl.AccessControlSections]::Access
            )
        }
    }

    $stage = "install_delayed_automatic"
    $installerPath = Join-Path $bundleRoot "install.ps1"
    $installInvocation = Invoke-NativeCapture `
        -Executable $pwshPath `
        -Arguments @(
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            $installerPath,
            "-HostConfigurationPath",
            $hostPath
        )
    if ($installInvocation.exit_code -ne 0) {
        throw [InvalidOperationException]::new("bundle installer failed")
    }
    $bundleInstalled = $true
    if (
        -not (Test-Path -LiteralPath $runtimePath -PathType Container) -or
        -not (Test-Path -LiteralPath $receiptPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $installedManifestPath -PathType Leaf)
    ) {
        throw [InvalidOperationException]::new("bundle installation is incomplete")
    }
    $service = Get-Service -Name $serviceName -ErrorAction Stop
    if ($service.Status -ne "Stopped") {
        throw [InvalidOperationException]::new("bundle installer unexpectedly started the service")
    }
    $serviceCim = Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'"
    if (
        $serviceCim.StartMode -ne "Auto" -or
        -not [string]::Equals(
            [string]$serviceCim.StartName,
            $servicePrincipal,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        $serviceCim.PathName -notlike "*$(Join-Path $runtimePath 'pythonservice.exe')*"
    ) {
        throw [InvalidOperationException]::new("installed service mode, account, or image is not exact")
    }
    $serviceRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
    $delayedAutoStart = Get-ItemPropertyValue `
        -LiteralPath $serviceRegistryPath `
        -Name "DelayedAutostart"
    $delayedValueKind = (Get-Item -LiteralPath $serviceRegistryPath).GetValueKind(
        "DelayedAutostart"
    )
    if (
        $delayedAutoStart -ne 1 -or
        $delayedValueKind -ne [Microsoft.Win32.RegistryValueKind]::DWord
    ) {
        throw [InvalidOperationException]::new("installed service is not delayed automatic")
    }
    $receiptBytes = [IO.File]::ReadAllBytes($receiptPath)
    $receipt = ConvertFrom-ClosedJsonBytes -Bytes $receiptBytes -Label "installation receipt"
    if (
        $receipt.manifest_sha256 -ne $manifestHash -or
        $receipt.host_configuration_sha256 -ne $hostSha256 -or
        $receipt.automatic_start -ne $true -or
        $receipt.removal_started -ne $false
    ) {
        throw [InvalidDataException]::new("installation receipt does not bind delayed-auto inputs")
    }
    $recovery = Assert-ExactRecoveryPolicy

    $stage = "write_protected_state"
    $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
    $preparedBootTime = ([DateTimeOffset]$operatingSystem.LastBootUpTime).ToUniversalTime()
    $preparedAt = [DateTimeOffset]::UtcNow
    $state = [ordered]@{
        schema_version = "1.0"
        qualification_id = [Guid]::NewGuid().ToString("N")
        prepared_at_utc = $preparedAt.ToString("O")
        prepared_boot_time_utc = $preparedBootTime.ToString("O")
        qualification_root = $qualificationRoot
        report_path = $reportPath
        scheduled_task_name = $taskName
        pwsh_path = $pwshPath
        completion_script_path = $completionPath
        completion_script_sha256 = $completionHash
        package_version = $packageVersion
        service_name = $serviceName
        service_principal = $servicePrincipal
        runtime_path = $runtimePath
        receipt_path = $receiptPath
        receipt_backup_path = $receiptBackupPath
        installed_manifest_path = $installedManifestPath
        host_configuration_path = $hostPath
        host_configuration_sha256 = $hostSha256
        refresh_configuration_path = $refreshPath
        refresh_configuration_sha256 = $refreshSha256
        trust_store_path = $trustPath
        database_path = $databasePath
        port = $Port
        bundle_sha256 = $bundleHash
        manifest_sha256 = $manifestHash
        manifest_file_count = @($manifest.files).Count
        operator_acl_baselines = $operatorAclBaselines
    }
    Write-AtomicJson -Path $statePath -Value $state
    Protect-File -Path $statePath
    $stateHash = (Get-FileHash -LiteralPath $statePath -Algorithm SHA256).Hash.ToLowerInvariant()

    $stage = "arm_startup_task"
    $taskArguments = (
        "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass " +
        "-File $completionPath -StatePath $statePath -StateSha256 $stateHash"
    )
    $action = New-ScheduledTaskAction `
        -Execute $pwshPath `
        -Argument $taskArguments `
        -WorkingDirectory $reportRoot
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $trigger.Delay = "PT30S"
    $principal = New-SystemPrincipal
    $settings = New-QualificationTaskSettings
    $registeredTask = Register-ScheduledTask `
        -TaskName $taskName `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Description "One-shot Causure cold-boot service qualification"
    $startupTaskRegistered = $true
    if (
        @($registeredTask.Actions).Count -ne 1 -or
        -not [string]::Equals(
            [string]$registeredTask.Actions[0].Execute,
            $pwshPath,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        $registeredTask.Actions[0].Arguments -ne $taskArguments -or
        $registeredTask.Actions[0].WorkingDirectory -ne $reportRoot -or
        $registeredTask.Principal.UserId -notin @("SYSTEM", "S-1-5-18") -or
        @($registeredTask.Triggers).Count -ne 1 -or
        $registeredTask.Triggers[0].CimClass.CimClassName -ne "MSFT_TaskBootTrigger" -or
        $registeredTask.Triggers[0].Delay -ne "PT30S"
    ) {
        throw [InvalidOperationException]::new("registered startup task is not exact")
    }
    if (
        (Get-Service -Name $serviceName).Status -ne "Stopped" -or
        (Test-Path -LiteralPath $reportPath)
    ) {
        throw [InvalidOperationException]::new("qualification changed state while arming")
    }

    $result = [ordered]@{
        schema_version = "1.0"
        result = "armed"
        qualification_id = $state.qualification_id
        package_version = $packageVersion
        bundle_sha256 = $bundleHash
        manifest_sha256 = $manifestHash
        completion_script_sha256 = $completionHash
        state_sha256 = $stateHash
        service_name = $serviceName
        service_state = "stopped"
        start_mode = "delayed_automatic"
        recovery_policy_verified = ($recovery.apply_on_non_crash_failures -eq $true)
        system_powershell_probe = "passed"
        scheduled_task_name = $taskName
        scheduled_task_principal = "NT AUTHORITY\SYSTEM"
        scheduled_task_trigger = "startup_after_30_seconds"
        report_path = $reportPath
        reboot_required = $true
    }
    $armed = $true
}
catch {
    $originalError = $_
}
finally {
    if (-not $armed) {
        foreach ($fixedTask in @($taskName, $probeTaskName)) {
            try {
                if ($null -ne (Get-ScheduledTask -TaskName $fixedTask -ErrorAction SilentlyContinue)) {
                    Unregister-ScheduledTask -TaskName $fixedTask -Confirm:$false
                }
            }
            catch {
                $cleanupErrors.Add("scheduled task cleanup failed")
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
                if ($stopInvocation.exit_code -ne 0) {
                    $cleanupErrors.Add("service stop cleanup failed")
                }
                $null = Wait-ServiceStopped -Seconds 60
            }
            $removerPath = Join-Path $runtimePath "management\remove.ps1"
            if (
                (Test-Path -LiteralPath $removerPath -PathType Leaf) -and
                (Test-Path -LiteralPath $receiptPath -PathType Leaf)
            ) {
                $cleanupPwsh = (Get-Command pwsh.exe -ErrorAction Stop).Source
                $removeInvocation = Invoke-NativeCapture `
                    -Executable $cleanupPwsh `
                    -Arguments @(
                        "-NoLogo",
                        "-NoProfile",
                        "-NonInteractive",
                        "-File",
                        $removerPath
                    )
                if ($removeInvocation.exit_code -ne 0) {
                    $cleanupErrors.Add("bundle remover cleanup failed")
                }
            }
        }
        catch {
            $cleanupErrors.Add("bundle cleanup failed")
        }
        try {
            $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            $runtimePython = Join-Path $runtimePath "python.exe"
            if ($null -ne $existingService -and $existingService.Status -ne "Stopped") {
                $null = & "$env:SystemRoot\System32\sc.exe" stop $serviceName 2>&1
                $null = Wait-ServiceStopped -Seconds 60
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
        }
        catch {
            $cleanupErrors.Add("service registration cleanup failed")
        }
        $serviceAbsent = Wait-ServiceAbsent -Seconds 20
        if ($serviceAbsent) {
            foreach ($managedPath in @(
                    $runtimePath,
                    $receiptPath,
                    $receiptBackupPath,
                    $installedManifestPath
                )) {
                if (Test-Path -LiteralPath $managedPath) {
                    try {
                        if ($managedPath -eq $runtimePath) {
                            $resolvedRuntime = (Resolve-Path -LiteralPath $runtimePath).Path
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
        if (
            $rootCreated -and
            $serviceAbsent -and
            (Test-Path -LiteralPath $qualificationRoot)
        ) {
            try {
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
        elseif ($rootCreated -and (Test-Path -LiteralPath $qualificationRoot)) {
            $cleanupErrors.Add("qualification root retained because the service remains registered")
        }
        if ($reportRootCreated -and (Test-Path -LiteralPath $reportRoot)) {
            try {
                $resolvedReportRoot = (Resolve-Path -LiteralPath $reportRoot).Path
                if (-not [string]::Equals(
                        $resolvedReportRoot,
                        $reportRoot,
                        [StringComparison]::OrdinalIgnoreCase
                    )) {
                    throw [InvalidOperationException]::new("report cleanup path is unexpected")
                }
                Remove-Item -LiteralPath $resolvedReportRoot -Recurse -Force
            }
            catch {
                $cleanupErrors.Add("report root cleanup failed")
            }
        }
    }
}

if (-not $armed) {
    if ($cleanupErrors.Count -ne 0) {
        throw [InvalidOperationException]::new(
            "cold-boot preparation failed and cleanup was incomplete: " +
            ($cleanupErrors -join ",")
        )
    }
    throw $originalError
}

$result | ConvertTo-Json -Depth 10
