"""Offline Windows service bundle policy and PowerShell syntax tests."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import unittest

from tests.helpers import PROJECT_ROOT

SCRIPT_ROOT = PROJECT_ROOT / "scripts"
BUILD_SCRIPT = SCRIPT_ROOT / "build_windows_service_bundle.ps1"
INSTALL_SCRIPT = SCRIPT_ROOT / "install_windows_service_bundle.ps1"
REMOVE_SCRIPT = SCRIPT_ROOT / "remove_windows_service_bundle.ps1"
QUALIFY_SCRIPT = SCRIPT_ROOT / "qualify_windows_service_bundle.ps1"
COLD_BOOT_PREPARE_SCRIPT = SCRIPT_ROOT / "prepare_windows_service_cold_boot_qualification.ps1"
COLD_BOOT_COMPLETE_SCRIPT = SCRIPT_ROOT / "complete_windows_service_cold_boot_qualification.ps1"
COLD_BOOT_EVIDENCE = (
    PROJECT_ROOT / "docs" / "qualifications" / "windows-service-cold-boot-2026-08-09.json"
)
MANIFEST_SCHEMA = PROJECT_ROOT / "schemas" / "windows-service-bundle-manifest.schema.json"
RECEIPT_SCHEMA = PROJECT_ROOT / "schemas" / "windows-service-installation-receipt.schema.json"
QUALIFIED_WINDOWS_SERVICE_PACKAGE_VERSION = "0.4.0a15"


class WindowsServiceBundleScriptTests(unittest.TestCase):
    def test_cold_boot_evidence_is_exact_passed_and_self_cleaning(self) -> None:
        evidence_bytes = COLD_BOOT_EVIDENCE.read_bytes()
        self.assertEqual(
            "0cf527aa4dbae066adb9d6f113e9da2c0e2e807bd05d1e7912ea5fa78b8ca734",
            hashlib.sha256(evidence_bytes).hexdigest(),
        )
        evidence = json.loads(evidence_bytes)

        self.assertEqual("passed", evidence["result"])
        self.assertTrue(evidence["os"]["reboot_observed"])
        self.assertEqual(
            QUALIFIED_WINDOWS_SERVICE_PACKAGE_VERSION,
            evidence["bundle"]["package_version"],
        )
        self.assertEqual(
            "16ee1b521d70fa0670e1c2099843bc8a2ae22dd9520772748d6345ec1b6daf04",
            evidence["bundle"]["bundle_sha256"],
        )
        self.assertEqual(3318, evidence["bundle"]["manifest_file_count"])
        self.assertTrue(evidence["installation"]["delayed_automatic"])
        self.assertTrue(evidence["installation"]["post_boot_non_crash_failure_flag"])
        self.assertEqual(200, evidence["cold_boot"]["health_status"])
        self.assertEqual(200, evidence["cold_boot"]["readiness_status"])

        unavailable = evidence["network_unavailable"]
        self.assertEqual(
            "structured_scm_failure_events",
            unavailable["recovery_observation_method"],
        )
        self.assertEqual(7031, unavailable["first_failure_event_id"])
        self.assertEqual(120000, unavailable["first_failure_restart_delay_milliseconds"])
        self.assertEqual(1, unavailable["first_failure_action_code"])
        self.assertEqual(7034, unavailable["second_failure_event_id"])
        self.assertEqual(2, unavailable["second_failure_count"])
        self.assertGreaterEqual(unavailable["recovery_elapsed_seconds"], 110)
        self.assertLessEqual(unavailable["recovery_elapsed_seconds"], 210)
        for assertion in (
            "first_failure_restarted",
            "second_failure_stopped_without_loop",
            "first_failure_health_unavailable",
            "first_failure_readiness_unavailable",
            "second_failure_health_unavailable",
            "second_failure_readiness_unavailable",
            "non_crash_policy_effective_after_boot",
            "exact_recovery_policy_remained",
            "last_known_good_restored_exactly",
            "firewall_rule_removed",
        ):
            with self.subTest(assertion=assertion):
                self.assertTrue(unavailable[assertion])

        self.assertEqual(200, evidence["restoration"]["health_status"])
        self.assertEqual(200, evidence["restoration"]["readiness_status"])
        self.assertTrue(all(evidence["removal"].values()))
        self.assertEqual([], evidence["cleanup"]["errors"])
        self.assertTrue(all(value for key, value in evidence["cleanup"].items() if key != "errors"))

    def test_manifest_and_receipt_schemas_are_closed_and_release_bound(self) -> None:
        for schema_path in (MANIFEST_SCHEMA, RECEIPT_SCHEMA):
            with self.subTest(schema=schema_path.name):
                schema = json.loads(schema_path.read_text(encoding="utf-8"))
                self.assertFalse(schema["additionalProperties"])
                self.assertEqual(
                    QUALIFIED_WINDOWS_SERVICE_PACKAGE_VERSION,
                    schema["properties"]["package_version"]["const"],
                )

    def test_scripts_share_the_release_and_fail_closed_shell_defaults(self) -> None:
        for script in (
            BUILD_SCRIPT,
            INSTALL_SCRIPT,
            REMOVE_SCRIPT,
            QUALIFY_SCRIPT,
            COLD_BOOT_PREPARE_SCRIPT,
            COLD_BOOT_COMPLETE_SCRIPT,
        ):
            with self.subTest(script=script.name):
                text = script.read_text(encoding="utf-8")
                self.assertIn("Set-StrictMode -Version Latest", text)
                self.assertIn('$ErrorActionPreference = "Stop"', text)
        self.assertIn(
            f'$supportedPackageVersion = "{QUALIFIED_WINDOWS_SERVICE_PACKAGE_VERSION}"',
            INSTALL_SCRIPT.read_text(encoding="utf-8"),
        )
        self.assertIn(
            f'$supportedPackageVersion = "{QUALIFIED_WINDOWS_SERVICE_PACKAGE_VERSION}"',
            REMOVE_SCRIPT.read_text(encoding="utf-8"),
        )
        self.assertIn(
            f'$packageVersion = "{QUALIFIED_WINDOWS_SERVICE_PACKAGE_VERSION}"',
            QUALIFY_SCRIPT.read_text(encoding="utf-8"),
        )

    def test_builder_is_offline_closed_and_reproducible(self) -> None:
        text = BUILD_SCRIPT.read_text(encoding="utf-8")

        for required in (
            '"--no-index"',
            '"--only-binary=:all:"',
            '"--no-compile"',
            "PipWheelPath",
            "runpy.run_module('pip',run_name='__main__')",
            '"RECORD"',
            '"direct_url.json"',
            '"bin"',
            "bundle-manifest.json",
            "Get-FileHash",
            "ReparsePoint",
            "$normalizedTimestamp",
            "ZipArchive",
        ):
            self.assertIn(required, text)
        self.assertNotIn("Invoke-WebRequest", text)

    def test_installer_binds_fixed_paths_integrity_acl_and_recovery(self) -> None:
        text = INSTALL_SCRIPT.read_text(encoding="utf-8")

        for required in (
            r"C:\Program Files\Causure\Team",
            r"C:\ProgramData\Causure\windows-service-installation.json",
            "windows-service-installation.removal-backup.json",
            "Assert-ExactProperties",
            "Resolve-ClosedRelativePath",
            "Get-FileHash",
            "ReparsePoint",
            "recovery-status",
            "120000",
            "NT AUTHORITY\\SYSTEM:(OI)(CI)(F)",
            "BUILTIN\\Administrators:(OI)(CI)(F)",
            "operatorAclBackups",
            "Assert-ClosedRuntimeAcl",
            "service_still_registered",
        ):
            self.assertIn(required, text)
        self.assertNotIn("Start-Service", text)
        runtime_acl_start = text.index("Grant-CheckedAcl `\n        -Path $finalRuntimePath")
        runtime_acl_end = text.index("foreach ($readPath", runtime_acl_start)
        runtime_acl_block = text[runtime_acl_start:runtime_acl_end]
        self.assertNotIn('"/T"', runtime_acl_block)
        self.assertNotIn('"/C"', runtime_acl_block)

    def test_remover_is_retry_safe_and_preserves_operator_state(self) -> None:
        text = REMOVE_SCRIPT.read_text(encoding="utf-8")

        for required in (
            "removal_started",
            "unmanifested file",
            "managed runtime integrity verification failed",
            "Invoke-ServiceCli",
            "operator_acl_backups",
            "SetSecurityDescriptorSddlForm",
            "operator_configuration_preserved = $true",
            "operator_state_and_data_preserved = $true",
            "managed runtime remained after removal",
            "if (-not $receipt.removal_started)",
            "windows-service-installation.removal-backup.json",
            "Protect-Receipt -Path $temporaryReceipt",
            "$fixedRemovalReceiptBackupPath",
        ):
            self.assertIn(required, text)
        self.assertNotIn("host_configuration_path -Recurse", text)
        self.assertNotIn(
            "[IO.File]::Replace($temporaryReceipt, $fixedReceiptPath, $null",
            text,
        )
        self.assertLess(
            text.index("Remove-Item -LiteralPath $resolvedRuntime"),
            text.index("Remove-Item -LiteralPath $fixedReceiptPath"),
        )

    def test_live_harness_covers_crash_and_closed_failure_modes(self) -> None:
        text = QUALIFY_SCRIPT.read_text(encoding="utf-8")

        for required in (
            "Stop-Process -Id $initialPid -Force",
            "$recoveryElapsedSeconds -lt 110",
            "configuration_drift_failure",
            "port_collision_failure",
            "stopped_without_loop",
            "operator_paths_preserved",
            "Invoke-NativeCapture",
            "failure_native_output",
            "errors = @($cleanupErrors)",
            "receipt_backup_absent",
            'reason = "reboot requires separate explicit operator authorization"',
        ):
            self.assertIn(required, text)

    def test_cold_boot_harness_is_hash_bound_one_shot_and_self_cleaning(self) -> None:
        prepare = COLD_BOOT_PREPARE_SCRIPT.read_text(encoding="utf-8")
        complete = COLD_BOOT_COMPLETE_SCRIPT.read_text(encoding="utf-8")

        for required in (
            "16ee1b521d70fa0670e1c2099843bc8a2ae22dd9520772748d6345ec1b6daf04",
            "2a625fb8af7e7b0ef1bed119fab055772c5870660c40234c29fe342747b41eab",
            '$probeTaskName = "CausureColdBootQualification-SystemProbe"',
            "LocalSystem PowerShell probe",
            "New-ScheduledTaskTrigger -AtStartup",
            '$trigger.Delay = "PT30S"',
            "-StateSha256 $stateHash",
            'start_mode = "delayed_automatic"',
            "-WorkingDirectory $reportRoot",
            "reboot_required = $true",
        ):
            self.assertIn(required, prepare)

        for required in (
            "Test-IsSystem",
            "qualification state digest does not match the task binding",
            "completion did not run after a new system boot",
            "Get-ExactServiceConfiguration",
            "post_boot_non_crash_failure_flag",
            "New-NetFirewallRule",
            "-Program $serviceExecutable",
            "Move-Item -LiteralPath $trustPath -Destination $trustBackupPath",
            "Start-ServiceWithoutWaiting",
            "[ServiceProcess.ServiceController]::new($serviceName)",
            "$controller.Start()",
            'start_request_method = "non_waiting_scm"',
            "Find-ExactScmFailureEvent",
            "Wait-ExactScmFailureEvent",
            'ProviderName = "Service Control Manager"',
            "-EventId 7031",
            "-FailureCount 1",
            "-RestartDelayMilliseconds 120000",
            "-ActionCode 1",
            "-EventId 7034",
            "-FailureCount 2",
            "-FailureCount 3",
            'recovery_observation_method = "structured_scm_failure_events"',
            "first_failure_event_record_id",
            "second_failure_event_record_id",
            "$nonCrashRecoverySeconds -lt 110",
            "non_crash_policy_effective_after_boot",
            "Assert-ProbesUnavailable",
            "first_failure_readiness_unavailable",
            "second_failure_readiness_unavailable",
            "[Environment]::CurrentDirectory = $reportRoot",
            "Set-Location -LiteralPath $reportRoot",
            "workstation_adapter_changed = $false",
            "global_firewall_policy_changed = $false",
            "Unregister-ScheduledTask",
            "startup_task_absent",
            "firewall_rule_absent",
        ):
            self.assertIn(required, complete)

        negative_start = complete.index('$stage = "non_crash_recovery"')
        stopped_wait = complete.index(
            "if (-not (Wait-ServiceStopped -Seconds 75))",
            negative_start,
        )
        negative_start_block = complete[negative_start:stopped_wait]
        self.assertIn("Start-ServiceWithoutWaiting", negative_start_block)
        self.assertNotIn("Invoke-ServiceCli", negative_start_block)
        self.assertNotIn('$recoveredCim.State -eq "Running"', complete)
        self.assertNotIn(
            "[int]$recoveredCim.ProcessId -ne $firstFailurePid",
            complete,
        )

        for forbidden in ("Disable-NetAdapter", "Set-NetFirewallProfile", "Restart-Computer"):
            self.assertNotIn(forbidden, prepare)
            self.assertNotIn(forbidden, complete)

    @unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is unavailable")
    def test_powershell_scripts_parse_without_errors(self) -> None:
        command = (
            "$tokens=$null;$errors=$null;"
            "[Management.Automation.Language.Parser]::ParseFile("
            "$env:CAUSURE_SCRIPT_TO_PARSE,[ref]$tokens,[ref]$errors)|Out-Null;"
            "if($errors.Count){$errors|ForEach-Object{Write-Error $_.Message};exit 1}"
        )
        for script in (
            BUILD_SCRIPT,
            INSTALL_SCRIPT,
            REMOVE_SCRIPT,
            QUALIFY_SCRIPT,
            COLD_BOOT_PREPARE_SCRIPT,
            COLD_BOOT_COMPLETE_SCRIPT,
        ):
            with self.subTest(script=script.name):
                environment = os.environ.copy()
                environment["CAUSURE_SCRIPT_TO_PARSE"] = str(script)
                result = subprocess.run(
                    ["pwsh", "-NoProfile", "-Command", command],
                    check=False,
                    capture_output=True,
                    env=environment,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
    unittest.main()
