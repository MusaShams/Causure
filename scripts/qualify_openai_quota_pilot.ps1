[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^(?:sha256:[a-f0-9]{64}|[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64})$")]
    [string]$CoreImage,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^(?:sha256:[a-f0-9]{64}|[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64})$")]
    [string]$EdgeImage,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$StateDirectory,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ReportPath,

    [ValidateNotNullOrEmpty()]
    [string]$PythonCommand = "python",

    [ValidateNotNullOrEmpty()]
    [string]$DockerCommand = "docker",

    [ValidateRange(1024, 65535)]
    [int]$AdminPort = 19443
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$PSNativeCommandUseErrorActionPreference = $false

$projectRoot = Split-Path -Parent $PSScriptRoot
$composePath = Join-Path $projectRoot "deploy\openai-quota-pilot\compose.yaml"
$coreDockerfile = Join-Path $projectRoot "deploy\openai-quota-pilot\Dockerfile"
$edgeDockerfile = Join-Path $projectRoot "deploy\openai-quota-pilot\Dockerfile.edge"
$workerCaddyfile = Join-Path $projectRoot "deploy\openai-quota-pilot\Caddyfile.worker"
$adminCaddyfile = Join-Path $projectRoot "deploy\openai-quota-pilot\Caddyfile.admin"
$buildScript = Join-Path $PSScriptRoot "build_openai_quota_pilot.ps1"
$qualificationScript = $MyInvocation.MyCommand.Path
$pythonProbeImage = "python@sha256:9662417aace5ae7b8e2609cce472b72a8958e134ba372808abe9cc1a0c0125e6"
$containerNames = @("openai-quota-core", "openai-quota", "openai-quota-admin")
$networkNames = @(
    "causure-quota",
    "causure-quota-backend",
    "causure-quota-egress",
    "causure-quota-admin-control"
)
$volumeName = "causure-openai-quota-data"
$startedAt = [DateTimeOffset]::UtcNow
$stage = "preflight"
$composeAttempted = $false
$passed = $false
$failureType = $null
$failureMessage = $null
$cleanupErrors = [Collections.Generic.List[string]]::new()
$evidence = [ordered]@{}
$previousEnvironment = @{
    CAUSURE_QUOTA_CORE_IMAGE = $env:CAUSURE_QUOTA_CORE_IMAGE
    CAUSURE_QUOTA_EDGE_IMAGE = $env:CAUSURE_QUOTA_EDGE_IMAGE
    CAUSURE_QUOTA_PILOT_STATE = $env:CAUSURE_QUOTA_PILOT_STATE
    CAUSURE_QUOTA_ADMIN_PORT = $env:CAUSURE_QUOTA_ADMIN_PORT
    PYTHONPATH = $env:PYTHONPATH
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
        throw [InvalidOperationException]::new(
            "$Operation failed with exit code $LASTEXITCODE"
        )
    }
    return ($output -join "`n")
}

function Test-DockerObjectExists {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("container", "network", "volume", "image")]
        [string]$Kind,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $null = & $DockerCommand $Kind inspect $Name 2>$null
    return $LASTEXITCODE -eq 0
}

function Wait-AdminReady {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CaPath,

        [ValidateRange(1, 60)]
        [int]$Seconds = 30
    )

    $probe = (
        "import ssl,sys,urllib.request; " +
        "ctx=ssl.create_default_context(cafile=sys.argv[1]); " +
        "op=urllib.request.build_opener(urllib.request.ProxyHandler({})," +
        "urllib.request.HTTPSHandler(context=ctx)); " +
        "r=op.open(sys.argv[2]+'/readyz',timeout=3); " +
        "print(r.status); r.close()"
    )
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($Seconds)
    do {
        try {
            $status = @(& $PythonCommand -c $probe $CaPath "https://localhost:$AdminPort" 2>$null)
            if ($LASTEXITCODE -eq 0 -and ($status -join "").Trim() -eq "200") {
                return $true
            }
        }
        catch {
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    return $false
}

function Restore-EnvironmentValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [AllowNull()]
        [string]$Value
    )

    if ($null -eq $Value) {
        Remove-Item -LiteralPath "Env:$Name" -ErrorAction SilentlyContinue
    }
    else {
        Set-Item -LiteralPath "Env:$Name" -Value $Value
    }
}

$stateInput = $(
    if ([IO.Path]::IsPathRooted($StateDirectory)) {
        $StateDirectory
    }
    else {
        Join-Path $projectRoot $StateDirectory
    }
)
$reportInput = $(
    if ([IO.Path]::IsPathRooted($ReportPath)) {
        $ReportPath
    }
    else {
        Join-Path $projectRoot $ReportPath
    }
)
$resolvedState = (Resolve-Path -LiteralPath $stateInput).Path
$resolvedReport = [IO.Path]::GetFullPath($reportInput)
$reportParent = Split-Path -Parent $resolvedReport
if (-not (Test-Path -LiteralPath $reportParent -PathType Container)) {
    throw [InvalidOperationException]::new("qualification report parent does not exist")
}
if (Test-Path -LiteralPath $resolvedReport) {
    throw [InvalidOperationException]::new("qualification report already exists and will not be overwritten")
}

try {
    try {
        $requiredStateFiles = @(
            "pilot-state.json",
            "config\openai-quota.json",
            "config\openai-quota-host.json",
            "secrets\openai-provider-api-key",
            "secrets\openai-quota-admin-token",
            "tls\quota-server.crt",
            "tls\quota-server.key",
            "trust\pilot-ca.crt"
        )
        foreach ($relativePath in $requiredStateFiles) {
            if (-not (Test-Path -LiteralPath (Join-Path $resolvedState $relativePath) -PathType Leaf)) {
                throw [InvalidOperationException]::new("pilot state is incomplete")
            }
        }
        $manifest = Get-Content -LiteralPath (Join-Path $resolvedState "pilot-state.json") -Raw |
            ConvertFrom-Json
        if ($manifest.schema_version -ne "1.0" -or $manifest.package_version -ne "0.4.0a18") {
            throw [InvalidOperationException]::new("pilot state manifest contract mismatch")
        }
        if ($null -ne (Get-NetTCPConnection -LocalPort $AdminPort -ErrorAction SilentlyContinue)) {
            throw [InvalidOperationException]::new("qualification admin port is already in use")
        }

        $dockerVersion = (
            Invoke-CheckedNative `
                -Executable $DockerCommand `
                -Arguments @("version", "--format", "{{.Server.Version}}") `
                -Operation "Docker engine preflight"
        ).Trim()
        $dockerPlatform = (
            Invoke-CheckedNative `
                -Executable $DockerCommand `
                -Arguments @("info", "--format", "{{.OperatingSystem}}|{{.OSType}}|{{.Architecture}}") `
                -Operation "Docker platform preflight"
        ).Trim()
        $composeVersion = (
            Invoke-CheckedNative `
                -Executable $DockerCommand `
                -Arguments @("compose", "version", "--short") `
                -Operation "Docker Compose preflight"
        ).Trim()

        foreach ($containerName in $containerNames) {
            if (Test-DockerObjectExists -Kind container -Name $containerName) {
                throw [InvalidOperationException]::new("fixed pilot container already exists")
            }
        }
        foreach ($networkName in $networkNames) {
            if (Test-DockerObjectExists -Kind network -Name $networkName) {
                throw [InvalidOperationException]::new("fixed pilot network already exists")
            }
        }
        if (Test-DockerObjectExists -Kind volume -Name $volumeName) {
            throw [InvalidOperationException]::new("fixed disposable pilot volume already exists")
        }
        foreach ($image in @($CoreImage, $EdgeImage, $pythonProbeImage)) {
            if (-not (Test-DockerObjectExists -Kind image -Name $image)) {
                throw [InvalidOperationException]::new("an exact qualification image is absent locally")
            }
        }

        $env:CAUSURE_QUOTA_CORE_IMAGE = $CoreImage
        $env:CAUSURE_QUOTA_EDGE_IMAGE = $EdgeImage
        $env:CAUSURE_QUOTA_PILOT_STATE = $resolvedState
        $env:CAUSURE_QUOTA_ADMIN_PORT = [string]$AdminPort
        $env:PYTHONPATH = Join-Path $projectRoot "src"

        $stage = "compose_start"
        $null = Invoke-CheckedNative `
            -Executable $DockerCommand `
            -Arguments @("compose", "--file", $composePath, "config", "--quiet") `
            -Operation "closed Compose rendering"
        $composeAttempted = $true
        $null = Invoke-CheckedNative `
            -Executable $DockerCommand `
            -Arguments @("compose", "--file", $composePath, "up", "--detach", "--wait") `
            -Operation "quota pilot startup"

        $caPath = Join-Path $resolvedState "trust\pilot-ca.crt"
        $adminTokenPath = Join-Path $resolvedState "secrets\openai-quota-admin-token"
        if (-not (Wait-AdminReady -CaPath $caPath -Seconds 30)) {
            throw [InvalidOperationException]::new("quota pilot did not become ready")
        }

        $stage = "route_isolation"
        $adminProbe = @'
import json
import ssl
import sys
import urllib.error
import urllib.request

ctx = ssl.create_default_context(cafile=sys.argv[1])
opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    urllib.request.HTTPSHandler(context=ctx),
)
base = sys.argv[2]
health = opener.open(base + "/healthz", timeout=3)
health_status = health.status
health.close()
ready = opener.open(base + "/readyz", timeout=3)
ready_status = ready.status
ready.close()
request = urllib.request.Request(
    base + "/v1/responses",
    data=b"{}",
    method="POST",
    headers={"Content-Type": "application/json"},
)
worker_route_blocked = False
try:
    opener.open(request, timeout=3)
except urllib.error.HTTPError as error:
    worker_route_blocked = error.code == 404
    error.close()
print(json.dumps({
    "health": health_status,
    "ready": ready_status,
    "worker_route_blocked": worker_route_blocked,
}))
'@
        $adminResult = (
            Invoke-CheckedNative `
                -Executable $PythonCommand `
                -Arguments @("-c", $adminProbe, $caPath, "https://localhost:$AdminPort") `
                -Operation "admin edge route probe"
        ) | ConvertFrom-Json
        if (
            $adminResult.health -ne 200 `
            -or $adminResult.ready -ne 200 `
            -or -not $adminResult.worker_route_blocked
        ) {
            throw [InvalidOperationException]::new("admin edge route contract failed")
        }

        $workerProbe = @'
import json
import ssl
import urllib.error
import urllib.request

ctx = ssl.create_default_context(cafile="/tmp/pilot-ca.crt")
opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    urllib.request.HTTPSHandler(context=ctx),
)
health = opener.open("https://openai-quota:8443/healthz", timeout=3)
health_status = health.status
health.close()
admin_route_blocked = False
try:
    opener.open("https://openai-quota:8443/admin/v1/leases", timeout=3)
except urllib.error.HTTPError as error:
    admin_route_blocked = error.code == 404
    error.close()
print(json.dumps({
    "health": health_status,
    "admin_route_blocked": admin_route_blocked,
}))
'@
        $caMount = "type=bind,source=$caPath,target=/tmp/pilot-ca.crt,readonly"
        $workerResult = (
            Invoke-CheckedNative `
                -Executable $DockerCommand `
                -Arguments @(
                    "run",
                    "--rm",
                    "--pull=never",
                    "--network",
                    "causure-quota",
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges=true",
                    "--mount",
                    $caMount,
                    $pythonProbeImage,
                    "python",
                    "-c",
                    $workerProbe
                ) `
                -Operation "worker edge route probe"
        ) | ConvertFrom-Json
        if ($workerResult.health -ne 200 -or -not $workerResult.admin_route_blocked) {
            throw [InvalidOperationException]::new("worker edge route contract failed")
        }

        $stage = "bypass_resistance"
        $quotaConfiguration = Get-Content `
            -LiteralPath (Join-Path $resolvedState "config\openai-quota.json") `
            -Raw | ConvertFrom-Json
        $providerHost = ([Uri]$quotaConfiguration.upstream_responses_url).DnsSafeHost
        $bypassProbe = @'
import json
import socket
import sys

connection = socket.socket()
connection.settimeout(3)
blocked = False
failure_type = ""
try:
    connection.connect((sys.argv[1], 443))
except OSError as error:
    blocked = True
    failure_type = type(error).__name__
finally:
    connection.close()
print(json.dumps({"blocked": blocked, "failure_type": failure_type}))
sys.exit(0 if blocked else 1)
'@
        $bypassResult = (
            Invoke-CheckedNative `
                -Executable $DockerCommand `
                -Arguments @(
                    "run",
                    "--rm",
                    "--pull=never",
                    "--network",
                    "causure-quota",
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges=true",
                    $pythonProbeImage,
                    "python",
                    "-c",
                    $bypassProbe,
                    $providerHost
                ) `
                -Operation "worker provider-bypass probe"
        ) | ConvertFrom-Json
        if (-not $bypassResult.blocked) {
            throw [InvalidOperationException]::new("worker reached the provider endpoint directly")
        }

        $stage = "restart_persistence"
        $reserveCode = (
            "import ssl,sys; from pathlib import Path; " +
            "from causure.openai_quota import HTTPSOpenAIQuotaAdminClient," +
            "OpenAIQuotaController; from causure.sandbox_protocol import QuotaReservation; " +
            "ctx=ssl.create_default_context(cafile=sys.argv[2]); " +
            "token=Path(sys.argv[1]).read_text(encoding='ascii'); " +
            "ctl=OpenAIQuotaController(HTTPSOpenAIQuotaAdminClient(sys.argv[3],token," +
            "ssl_context=ctx)); lease=ctl.reserve(QuotaReservation(case_id='pilot-qualification'," +
            "max_cost_usd=0.01,max_concurrency=1,max_operations=1,timeout_seconds=300.0)); " +
            "print(lease.lease_id)"
        )
        $leaseId = (
            Invoke-CheckedNative `
                -Executable $PythonCommand `
                -Arguments @(
                    "-c",
                    $reserveCode,
                    $adminTokenPath,
                    $caPath,
                    "https://localhost:$AdminPort"
                ) `
                -Operation "qualification lease reservation"
        ).Trim()
        if ($leaseId -notmatch '^oq-[a-f0-9]{32}$') {
            throw [InvalidOperationException]::new("quota core returned an invalid lease ID")
        }
        $null = Invoke-CheckedNative `
            -Executable $DockerCommand `
            -Arguments @("restart", "openai-quota-core") `
            -Operation "quota-core restart"
        if (-not (Wait-AdminReady -CaPath $caPath -Seconds 30)) {
            throw [InvalidOperationException]::new("quota core did not recover readiness")
        }
        $cancelCode = (
            "import ssl,sys; from pathlib import Path; " +
            "from causure.openai_quota import HTTPSOpenAIQuotaAdminClient," +
            "OpenAIQuotaController; ctx=ssl.create_default_context(cafile=sys.argv[2]); " +
            "token=Path(sys.argv[1]).read_text(encoding='ascii'); " +
            "ctl=OpenAIQuotaController(HTTPSOpenAIQuotaAdminClient(sys.argv[4],token," +
            "ssl_context=ctx)); ctl.cancel(sys.argv[3],reason_code='qualification_cleanup')"
        )
        $null = Invoke-CheckedNative `
            -Executable $PythonCommand `
            -Arguments @(
                "-c",
                $cancelCode,
                $adminTokenPath,
                $caPath,
                $leaseId,
                "https://localhost:$AdminPort"
            ) `
            -Operation "post-restart lease cancellation"

        $stage = "runtime_hardening"
        $containerDocuments = @(
            (
                Invoke-CheckedNative `
                    -Executable $DockerCommand `
                    -Arguments (@("inspect") + $containerNames) `
                    -Operation "pilot container inspection"
            ) | ConvertFrom-Json
        )
        $networkMembership = [ordered]@{}
        foreach ($container in $containerDocuments) {
            if (
                $container.Config.User -ne "65532:65532" `
                -or -not $container.HostConfig.ReadonlyRootfs `
                -or $container.HostConfig.Privileged `
                -or "ALL" -notin @($container.HostConfig.CapDrop) `
                -or "no-new-privileges=true" -notin @($container.HostConfig.SecurityOpt)
            ) {
                throw [InvalidOperationException]::new("runtime container hardening drifted")
            }
            $containerName = $container.Name.TrimStart("/")
            $actualNetworks = @(
                $container.NetworkSettings.Networks.PSObject.Properties.Name | Sort-Object
            )
            $expectedNetworks = switch ($containerName) {
                "openai-quota-core" {
                    @("causure-quota-backend", "causure-quota-egress")
                }
                "openai-quota" {
                    @("causure-quota", "causure-quota-backend")
                }
                "openai-quota-admin" {
                    @(
                        "causure-quota-admin-control",
                        "causure-quota-backend"
                    )
                }
                default {
                    throw [InvalidOperationException]::new("unexpected pilot container")
                }
            }
            $networkDifference = @(
                Compare-Object ($expectedNetworks | Sort-Object) $actualNetworks
            )
            if ($networkDifference.Count -ne 0) {
                throw [InvalidOperationException]::new("runtime network membership drifted")
            }
            $networkMembership[$containerName] = $actualNetworks
            foreach ($mount in @($container.Mounts)) {
                if (
                    $mount.Destination.StartsWith("/run/configs/") `
                    -or $mount.Destination.StartsWith("/run/secrets/") `
                    -or $mount.Destination -eq "/etc/caddy/Caddyfile"
                ) {
                    if ($mount.RW) {
                        throw [InvalidOperationException]::new(
                            "runtime protected mount became writable"
                        )
                    }
                }
            }
        }
        $adminContainer = @(
            $containerDocuments | Where-Object { $_.Name -eq "/openai-quota-admin" }
        )[0]
        $adminBindings = @($adminContainer.NetworkSettings.Ports.'9443/tcp')
        if (
            $adminBindings.Count -ne 1 `
            -or $adminBindings[0].HostIp -ne "127.0.0.1" `
            -or [int]$adminBindings[0].HostPort -ne $AdminPort
        ) {
            throw [InvalidOperationException]::new("admin listener was not loopback-only")
        }
        $workerNetworkDocument = @(
            (
                Invoke-CheckedNative `
                    -Executable $DockerCommand `
                    -Arguments @("network", "inspect", "causure-quota") `
                    -Operation "worker network inspection"
            ) | ConvertFrom-Json
        )[0]
        $workerMembers = @(
            $workerNetworkDocument.Containers.PSObject.Properties |
                ForEach-Object { $_.Value.Name }
        )
        if (
            -not $workerNetworkDocument.Internal `
            -or -not $workerNetworkDocument.Attachable `
            -or $workerMembers.Count -ne 1 `
            -or $workerMembers[0] -ne "openai-quota"
        ) {
            throw [InvalidOperationException]::new("worker network exclusivity drifted")
        }

        $resolvedCoreId = (
            Invoke-CheckedNative `
                -Executable $DockerCommand `
                -Arguments @("image", "inspect", "--format", "{{.Id}}", $CoreImage) `
                -Operation "quota-core image identity inspection"
        ).Trim()
        $resolvedEdgeId = (
            Invoke-CheckedNative `
                -Executable $DockerCommand `
                -Arguments @("image", "inspect", "--format", "{{.Id}}", $EdgeImage) `
                -Operation "quota-edge image identity inspection"
        ).Trim()
        foreach ($container in $containerDocuments) {
            $expectedImageId = $(
                if ($container.Name -eq "/openai-quota-core") {
                    $resolvedCoreId
                }
                else {
                    $resolvedEdgeId
                }
            )
            if ($container.Image -ne $expectedImageId) {
                throw [InvalidOperationException]::new("runtime image identity drifted")
            }
        }
        $evidence = [ordered]@{
            host_os = [Environment]::OSVersion.VersionString
            docker = [ordered]@{
                version = $dockerVersion
                compose_version = $composeVersion
                platform = $dockerPlatform
            }
            images = [ordered]@{
                quota_core_requested = $CoreImage
                quota_core_id = $resolvedCoreId
                quota_edge_requested = $EdgeImage
                quota_edge_id = $resolvedEdgeId
                probe_image = $pythonProbeImage
            }
            state_manifest_sha256 = (
                Get-FileHash `
                    -LiteralPath (Join-Path $resolvedState "pilot-state.json") `
                    -Algorithm SHA256
            ).Hash.ToLowerInvariant()
            deployment_subjects = [ordered]@{
                compose_sha256 = (
                    Get-FileHash -LiteralPath $composePath -Algorithm SHA256
                ).Hash.ToLowerInvariant()
                worker_edge_sha256 = (
                    Get-FileHash -LiteralPath $workerCaddyfile -Algorithm SHA256
                ).Hash.ToLowerInvariant()
                admin_edge_sha256 = (
                    Get-FileHash -LiteralPath $adminCaddyfile -Algorithm SHA256
                ).Hash.ToLowerInvariant()
                core_dockerfile_sha256 = (
                    Get-FileHash -LiteralPath $coreDockerfile -Algorithm SHA256
                ).Hash.ToLowerInvariant()
                edge_dockerfile_sha256 = (
                    Get-FileHash -LiteralPath $edgeDockerfile -Algorithm SHA256
                ).Hash.ToLowerInvariant()
                build_script_sha256 = (
                    Get-FileHash -LiteralPath $buildScript -Algorithm SHA256
                ).Hash.ToLowerInvariant()
                qualification_script_sha256 = (
                    Get-FileHash -LiteralPath $qualificationScript -Algorithm SHA256
                ).Hash.ToLowerInvariant()
            }
            health = [ordered]@{
                admin_health_status = $adminResult.health
                admin_readiness_status = $adminResult.ready
                worker_health_status = $workerResult.health
            }
            route_isolation = [ordered]@{
                worker_cannot_reach_admin = $workerResult.admin_route_blocked
                admin_cannot_reach_worker_responses = $adminResult.worker_route_blocked
            }
            network = [ordered]@{
                worker_internal = $workerNetworkDocument.Internal
                worker_attachable = $workerNetworkDocument.Attachable
                exclusive_member = $workerMembers[0]
                live_membership = $networkMembership
                admin_host_ip = $adminBindings[0].HostIp
                admin_host_port = [int]$adminBindings[0].HostPort
                direct_provider_tcp_blocked = $bypassResult.blocked
                blocked_failure_type = $bypassResult.failure_type
            }
            restart = [ordered]@{
                core_restarted = $true
                readiness_recovered = $true
                pre_restart_lease_canceled_after_restart = $true
            }
            runtime = [ordered]@{
                non_root_user = "65532:65532"
                read_only_roots = $true
                all_capabilities_dropped = $true
                no_new_privileges = $true
            }
            provider = [ordered]@{
                live_api_request_performed = $false
                invoice_reconciliation_performed = $false
            }
        }
        $passed = $true
    }
    catch {
        $failureType = $_.Exception.GetType().FullName
        $failureMessage = "qualification failed during $stage"
        $passed = $false
    }
    finally {
        if ($composeAttempted) {
            try {
                $null = Invoke-CheckedNative `
                    -Executable $DockerCommand `
                    -Arguments @(
                        "compose",
                        "--file",
                        $composePath,
                        "down",
                        "--volumes",
                        "--remove-orphans",
                        "--timeout",
                        "10"
                    ) `
                    -Operation "quota pilot cleanup"
            }
            catch {
                $cleanupErrors.Add("compose_cleanup_failed")
                $passed = $false
            }
        }
    }

    $containersAbsent = -not @(
        $containerNames | Where-Object { Test-DockerObjectExists -Kind container -Name $_ }
    )
    $networksAbsent = -not @(
        $networkNames | Where-Object { Test-DockerObjectExists -Kind network -Name $_ }
    )
    $volumeAbsent = -not (Test-DockerObjectExists -Kind volume -Name $volumeName)
    if (-not $containersAbsent -or -not $networksAbsent -or -not $volumeAbsent) {
        $cleanupErrors.Add("disposable_resources_remain")
        $passed = $false
    }

    $finishedAt = [DateTimeOffset]::UtcNow
    $report = [ordered]@{
        schema_version = "1.0"
        result = $(if ($passed) { "passed" } else { "failed" })
        scope = "offline-local-pilot-no-provider-request"
        package_version = "0.4.0a18"
        started_at_utc = $startedAt.ToString("o")
        finished_at_utc = $finishedAt.ToString("o")
        evidence = $evidence
        cleanup = [ordered]@{
            containers_absent = $containersAbsent
            networks_absent = $networksAbsent
            disposable_volume_absent = $volumeAbsent
            prepared_state_preserved = (Test-Path -LiteralPath $resolvedState -PathType Container)
            errors = @($cleanupErrors)
        }
        limitations = @(
            "No provider API request or invoice reconciliation was performed.",
            "The admin control bridge is non-internal for Docker Desktop loopback publication.",
            "Docker daemon, host kernel, protected state ACLs, model identity, and prices remain trusted deployment inputs.",
            "This receipt is not production hard-spend qualification."
        )
        failure = $(
            if ($passed) {
                $null
            }
            else {
                [ordered]@{
                    stage = $stage
                    type = $failureType
                    message = $failureMessage
                }
            }
        )
    }
    $reportJson = $report | ConvertTo-Json -Depth 10
    $temporaryReport = Join-Path $reportParent ("." + [IO.Path]::GetFileName($resolvedReport) + ".tmp")
    if (Test-Path -LiteralPath $temporaryReport) {
        throw [InvalidOperationException]::new("qualification report staging path already exists")
    }
    [IO.File]::WriteAllText(
        $temporaryReport,
        $reportJson + "`n",
        [Text.UTF8Encoding]::new($false)
    )
    Move-Item -LiteralPath $temporaryReport -Destination $resolvedReport

    if (-not $passed) {
        throw [InvalidOperationException]::new(
            "OpenAI quota pilot qualification failed; inspect the secret-free report"
        )
    }
    Write-Host "OpenAI quota pilot offline qualification passed: $resolvedReport"
}
finally {
    Restore-EnvironmentValue -Name "CAUSURE_QUOTA_CORE_IMAGE" -Value $previousEnvironment.CAUSURE_QUOTA_CORE_IMAGE
    Restore-EnvironmentValue -Name "CAUSURE_QUOTA_EDGE_IMAGE" -Value $previousEnvironment.CAUSURE_QUOTA_EDGE_IMAGE
    Restore-EnvironmentValue -Name "CAUSURE_QUOTA_PILOT_STATE" -Value $previousEnvironment.CAUSURE_QUOTA_PILOT_STATE
    Restore-EnvironmentValue -Name "CAUSURE_QUOTA_ADMIN_PORT" -Value $previousEnvironment.CAUSURE_QUOTA_ADMIN_PORT
    Restore-EnvironmentValue -Name "PYTHONPATH" -Value $previousEnvironment.PYTHONPATH
}
