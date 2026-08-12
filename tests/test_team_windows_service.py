"""Native Windows Team service policy, registration, and lifecycle tests."""

from __future__ import annotations

import contextlib
import hashlib
import io
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock, patch

from causure.team_host import (
    parse_team_host_configuration,
    render_team_host_configuration,
)
from causure.team_windows_service import (
    TEAM_WINDOWS_SERVICE_ACCOUNT,
    TEAM_WINDOWS_SERVICE_CLASS,
    TEAM_WINDOWS_SERVICE_NAME,
    TEAM_WINDOWS_SERVICE_RECOVERY_RESET_SECONDS,
    TEAM_WINDOWS_SERVICE_RECOVERY_RESTART_DELAY_MILLISECONDS,
    TEAM_WINDOWS_SERVICE_REGISTRATION_VALUE,
    TeamWindowsServiceError,
    TeamWindowsServiceRecoveryAction,
    TeamWindowsServiceRecoveryPolicy,
    TeamWindowsServiceRegistration,
    _WindowsServiceModules,
    configure_team_windows_service,
    configure_team_windows_service_recovery_policy,
    get_team_windows_service_recovery_policy,
    get_team_windows_service_status,
    install_team_windows_service,
    load_registered_team_host_configuration,
    parse_team_windows_service_registration,
    parse_team_windows_service_registration_text,
    prepare_team_windows_service_registration,
    remove_team_windows_service,
    render_team_windows_service_registration,
    start_team_windows_service,
    stop_team_windows_service,
)
from causure.team_windows_service_cli import main as service_main
from tests.test_team_host import _host_document


class _FakeWin32Service:
    SERVICE_STOPPED = 1
    SERVICE_START_PENDING = 2
    SERVICE_STOP_PENDING = 3
    SERVICE_RUNNING = 4
    SERVICE_CONTINUE_PENDING = 5
    SERVICE_PAUSE_PENDING = 6
    SERVICE_PAUSED = 7
    SERVICE_AUTO_START = 2
    SERVICE_DEMAND_START = 3
    SERVICE_DISABLED = 4
    SERVICE_NO_CHANGE = 0xFFFFFFFF
    SC_MANAGER_CONNECT = 1
    SERVICE_QUERY_CONFIG = 1
    SERVICE_CHANGE_CONFIG = 2
    SERVICE_START = 16
    SERVICE_CONFIG_FAILURE_ACTIONS = 2
    SERVICE_CONFIG_FAILURE_ACTIONS_FLAG = 4
    SERVICE_CONFIG_SERVICE_SID_INFO = 5
    SERVICE_SID_TYPE_UNRESTRICTED = 1
    SC_ACTION_NONE = 0
    SC_ACTION_RESTART = 1
    SC_ACTION_REBOOT = 2
    SC_ACTION_RUN_COMMAND = 3

    def __init__(self) -> None:
        self.sid_calls: list[tuple[Any, int, int]] = []
        self.config2_calls: list[tuple[Any, int, Any]] = []
        self.change_config_calls: list[tuple[Any, ...]] = []
        self.failure_actions: dict[str, Any] = {
            "ResetPeriod": 0,
            "RebootMsg": None,
            "Command": None,
            "Actions": (),
        }
        self.failure_actions_flag = False
        self.fail_config2_once_level: int | None = None
        self.start_type = self.SERVICE_DEMAND_START
        self.closed: list[Any] = []

    def OpenSCManager(self, machine: Any, database: Any, access: int) -> str:
        return "manager"

    def OpenService(self, manager: Any, name: str, access: int) -> str:
        return "service"

    def ChangeServiceConfig2(self, handle: Any, level: int, value: Any) -> None:
        if self.fail_config2_once_level == level:
            self.fail_config2_once_level = None
            raise OSError("configuration rejected")
        self.config2_calls.append((handle, level, value))
        if level == self.SERVICE_CONFIG_SERVICE_SID_INFO:
            self.sid_calls.append((handle, level, value))
        elif level == self.SERVICE_CONFIG_FAILURE_ACTIONS:
            self.failure_actions = {
                "ResetPeriod": value["ResetPeriod"],
                "RebootMsg": value["RebootMsg"],
                "Command": value["Command"],
                "Actions": tuple(tuple(action) for action in value["Actions"]),
            }
        elif level == self.SERVICE_CONFIG_FAILURE_ACTIONS_FLAG:
            self.failure_actions_flag = bool(value)
        else:
            raise AssertionError(f"unexpected ChangeServiceConfig2 level {level}")

    def QueryServiceConfig2(self, handle: Any, level: int) -> Any:
        if level == self.SERVICE_CONFIG_FAILURE_ACTIONS:
            return dict(self.failure_actions)
        if level == self.SERVICE_CONFIG_FAILURE_ACTIONS_FLAG:
            return self.failure_actions_flag
        raise AssertionError(f"unexpected QueryServiceConfig2 level {level}")

    def QueryServiceConfig(self, handle: Any) -> tuple[Any, ...]:
        return (16, self.start_type, 1, "pythonservice.exe", None, 0, (), None, "display")

    def ChangeServiceConfig(self, *args: Any) -> None:
        self.change_config_calls.append(args)
        self.start_type = args[2]

    def CloseServiceHandle(self, handle: Any) -> None:
        self.closed.append(handle)


class _FakeWin32ServiceUtil:
    def __init__(self, service: _FakeWin32Service) -> None:
        self.service = service
        self.state = service.SERVICE_STOPPED
        self.install_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self.remove_calls: list[str] = []
        self.start_calls: list[str] = []
        self.stop_calls: list[str] = []
        self.wait_calls: list[tuple[str, int, int]] = []
        self.fail_remove = False

    def InstallService(self, *args: Any, **kwargs: Any) -> None:
        self.install_calls.append((args, kwargs))

    def RemoveService(self, name: str) -> None:
        if self.fail_remove:
            raise OSError("remove rejected")
        self.remove_calls.append(name)

    def QueryServiceStatus(self, name: str) -> tuple[int, int, int, int, int, int, int]:
        return (16, self.state, 0, 0, 0, 0, 0)

    def StartService(self, name: str) -> None:
        self.start_calls.append(name)
        self.state = self.service.SERVICE_START_PENDING

    def StopService(self, name: str) -> None:
        self.stop_calls.append(name)
        self.state = self.service.SERVICE_STOP_PENDING

    def WaitForServiceStatus(self, name: str, state: int, seconds: int) -> None:
        self.wait_calls.append((name, state, seconds))
        self.state = state


class _FakeWinReg:
    HKEY_LOCAL_MACHINE = "HKLM"
    KEY_SET_VALUE = 2
    KEY_READ = 1
    REG_SZ = 1

    def __init__(self) -> None:
        self.values: dict[str, tuple[Any, int]] = {}
        self.fail_write = False
        self.closed: list[Any] = []

    def CreateKeyEx(self, root: Any, path: str, reserved: int, access: int) -> str:
        return path

    def OpenKey(self, root: Any, path: str, reserved: int, access: int) -> str:
        return path

    def SetValueEx(
        self,
        key: Any,
        name: str,
        reserved: int,
        value_type: int,
        value: Any,
    ) -> None:
        if self.fail_write:
            raise OSError("registry denied")
        self.values[name] = (value, value_type)

    def QueryValueEx(self, key: Any, name: str) -> tuple[Any, int]:
        if name not in self.values:
            raise OSError("missing value")
        return self.values[name]

    def CloseKey(self, key: Any) -> None:
        self.closed.append(key)


def _fake_modules() -> tuple[_WindowsServiceModules, _FakeWin32ServiceUtil, _FakeWinReg]:
    service = _FakeWin32Service()
    utility = _FakeWin32ServiceUtil(service)
    registry = _FakeWinReg()
    return _WindowsServiceModules(service, utility, registry), utility, registry


def _write_host_configuration(directory: str) -> tuple[Path, Any]:
    document, _ = _host_document(directory)
    configuration = parse_team_host_configuration(document)
    path = Path(directory) / "team-host.json"
    path.write_text(render_team_host_configuration(configuration), encoding="utf-8")
    return path, configuration


class TeamWindowsServiceRegistrationTests(unittest.TestCase):
    def test_registration_round_trip_is_closed_and_deterministic(self) -> None:
        registration = TeamWindowsServiceRegistration(
            schema_version="1.0",
            configuration_path=r"C:\Protected\team-host.json",
            configuration_sha256="a" * 64,
            configuration_byte_count=123,
        )

        rendered = render_team_windows_service_registration(registration)
        parsed = parse_team_windows_service_registration_text(rendered)

        self.assertEqual(registration, parsed)
        self.assertEqual(rendered, render_team_windows_service_registration(parsed))

    def test_registration_rejects_unknown_duplicate_and_invalid_subjects(self) -> None:
        valid = {
            "schema_version": "1.0",
            "configuration_path": r"C:\Protected\team-host.json",
            "configuration_sha256": "a" * 64,
            "configuration_byte_count": 123,
        }
        cases = []
        for key, value in (
            ("unexpected", True),
            ("configuration_path", "relative.json"),
            ("configuration_path", r"\\server\share\team-host.json"),
            ("configuration_sha256", "A" * 64),
            ("configuration_byte_count", 0),
        ):
            candidate = dict(valid)
            candidate[key] = value
            cases.append(candidate)
        for candidate in cases:
            with self.subTest(candidate=candidate):
                with self.assertRaises(TeamWindowsServiceError):
                    parse_team_windows_service_registration(candidate)
        with self.assertRaises(TeamWindowsServiceError):
            parse_team_windows_service_registration_text(
                '{"schema_version":"1.0","schema_version":"1.0"}'
            )

    @unittest.skipUnless(sys.platform == "win32", "host registration is Windows-only")
    def test_prepare_binds_exact_absolute_host_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path, _ = _write_host_configuration(directory)
            data = path.read_bytes()

            registration = prepare_team_windows_service_registration(path)

        self.assertEqual(str(path.resolve()), registration.configuration_path)
        self.assertEqual(hashlib.sha256(data).hexdigest(), registration.configuration_sha256)
        self.assertEqual(len(data), registration.configuration_byte_count)

    @unittest.skipUnless(sys.platform == "win32", "host registration is Windows-only")
    def test_registered_configuration_fails_after_exact_bytes_change(self) -> None:
        modules, _, registry = _fake_modules()
        with tempfile.TemporaryDirectory() as directory:
            path, configuration = _write_host_configuration(directory)
            registration = prepare_team_windows_service_registration(path)
            registry.values[TEAM_WINDOWS_SERVICE_REGISTRATION_VALUE] = (
                render_team_windows_service_registration(registration),
                registry.REG_SZ,
            )
            with patch(
                "causure.team_windows_service._load_windows_service_modules",
                return_value=modules,
            ):
                loaded = load_registered_team_host_configuration()
                changed_document, _ = _host_document(directory)
                changed_document["server"]["listen_port"] = 8081
                changed = parse_team_host_configuration(changed_document)
                path.write_text(render_team_host_configuration(changed), encoding="utf-8")
                with self.assertRaises(TeamWindowsServiceError) as raised:
                    load_registered_team_host_configuration()

        self.assertEqual(configuration, loaded)
        self.assertEqual("configuration_subject_mismatch", raised.exception.code)


class TeamWindowsServiceManagementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.modules, self.utility, self.registry = _fake_modules()
        self.registration = TeamWindowsServiceRegistration(
            schema_version="1.0",
            configuration_path=r"C:\Protected\team-host.json",
            configuration_sha256="b" * 64,
            configuration_byte_count=456,
        )
        self.module_patch = patch(
            "causure.team_windows_service._load_windows_service_modules",
            return_value=self.modules,
        )
        self.prepare_patch = patch(
            "causure.team_windows_service.prepare_team_windows_service_registration",
            return_value=self.registration,
        )
        self.module_patch.start()
        self.prepare_patch.start()

    def tearDown(self) -> None:
        self.prepare_patch.stop()
        self.module_patch.stop()

    def test_install_uses_virtual_account_sid_and_one_atomic_registry_value(self) -> None:
        installed = install_team_windows_service(
            r"C:\Protected\team-host.json",
            automatic_start=True,
        )

        self.assertEqual(self.registration, installed)
        args, kwargs = self.utility.install_calls[0]
        self.assertEqual(TEAM_WINDOWS_SERVICE_CLASS, args[0])
        self.assertEqual(TEAM_WINDOWS_SERVICE_NAME, args[1])
        self.assertEqual(TEAM_WINDOWS_SERVICE_ACCOUNT, kwargs["userName"])
        self.assertIsNone(kwargs["password"])
        self.assertTrue(kwargs["delayedstart"])
        self.assertEqual(self.modules.win32service.SERVICE_AUTO_START, kwargs["startType"])
        self.assertEqual(1, len(self.modules.win32service.sid_calls))
        self.assertEqual(
            {
                "ResetPeriod": TEAM_WINDOWS_SERVICE_RECOVERY_RESET_SECONDS,
                "RebootMsg": None,
                "Command": None,
                "Actions": (
                    (
                        self.modules.win32service.SC_ACTION_RESTART,
                        TEAM_WINDOWS_SERVICE_RECOVERY_RESTART_DELAY_MILLISECONDS,
                    ),
                    (self.modules.win32service.SC_ACTION_NONE, 0),
                ),
            },
            self.modules.win32service.failure_actions,
        )
        self.assertTrue(self.modules.win32service.failure_actions_flag)
        self.assertEqual(
            self.registration,
            parse_team_windows_service_registration_text(
                self.registry.values[TEAM_WINDOWS_SERVICE_REGISTRATION_VALUE][0]
            ),
        )

    def test_install_rolls_back_service_when_registration_write_fails(self) -> None:
        self.registry.fail_write = True

        with self.assertRaises(TeamWindowsServiceError) as raised:
            install_team_windows_service(r"C:\Protected\team-host.json")

        self.assertEqual("registration_write_failed", raised.exception.code)
        self.assertEqual([TEAM_WINDOWS_SERVICE_NAME], self.utility.remove_calls)

    def test_install_wraps_sid_failure_and_rolls_back_service(self) -> None:
        with (
            patch(
                "causure.team_windows_service._enable_service_sid",
                side_effect=OSError("sensitive system error"),
            ),
            self.assertRaises(TeamWindowsServiceError) as raised,
        ):
            install_team_windows_service(r"C:\Protected\team-host.json")

        self.assertEqual("service_setup_failed", raised.exception.code)
        self.assertNotIn("sensitive system error", str(raised.exception))
        self.assertEqual([TEAM_WINDOWS_SERVICE_NAME], self.utility.remove_calls)

    def test_configure_requires_stopped_service_and_replaces_subject(self) -> None:
        configured = configure_team_windows_service(r"C:\Protected\team-host.json")
        self.assertEqual(self.registration, configured)

        self.utility.state = self.modules.win32service.SERVICE_RUNNING
        with self.assertRaises(TeamWindowsServiceError) as raised:
            configure_team_windows_service(r"C:\Protected\team-host.json")
        self.assertEqual("service_not_stopped", raised.exception.code)

    def test_recovery_policy_is_closed_verified_and_requires_stopped_service(self) -> None:
        expected = TeamWindowsServiceRecoveryPolicy(
            reset_period_seconds=TEAM_WINDOWS_SERVICE_RECOVERY_RESET_SECONDS,
            actions=(
                TeamWindowsServiceRecoveryAction(
                    action_name="restart",
                    delay_milliseconds=TEAM_WINDOWS_SERVICE_RECOVERY_RESTART_DELAY_MILLISECONDS,
                ),
                TeamWindowsServiceRecoveryAction(action_name="none", delay_milliseconds=0),
            ),
            apply_on_non_crash_failures=True,
            reboot_message_configured=False,
            command_configured=False,
        )

        configured = configure_team_windows_service_recovery_policy()

        self.assertEqual(expected, configured)
        self.assertEqual(expected, get_team_windows_service_recovery_policy())
        self.utility.state = self.modules.win32service.SERVICE_RUNNING
        with self.assertRaises(TeamWindowsServiceError) as raised:
            configure_team_windows_service_recovery_policy()
        self.assertEqual("service_not_stopped", raised.exception.code)

    def test_recovery_policy_rolls_back_both_values_after_partial_failure(self) -> None:
        service = self.modules.win32service
        original_actions = dict(service.failure_actions)
        service.fail_config2_once_level = service.SERVICE_CONFIG_FAILURE_ACTIONS_FLAG

        with self.assertRaises(TeamWindowsServiceError) as raised:
            configure_team_windows_service_recovery_policy()

        self.assertEqual("service_recovery_configure_failed", raised.exception.code)
        self.assertEqual(original_actions, service.failure_actions)
        self.assertFalse(service.failure_actions_flag)

    def test_start_stop_status_and_idempotent_terminal_states(self) -> None:
        started = start_team_windows_service(wait_seconds=12)
        self.assertEqual("running", started.state_name)
        self.assertEqual(
            [(TEAM_WINDOWS_SERVICE_NAME, self.modules.win32service.SERVICE_RUNNING, 12)],
            self.utility.wait_calls,
        )
        self.assertEqual(started, start_team_windows_service(wait_seconds=12))

        stopped = stop_team_windows_service(wait_seconds=13)
        self.assertEqual("stopped", stopped.state_name)
        self.assertEqual(stopped, stop_team_windows_service(wait_seconds=13))
        self.assertEqual(stopped, get_team_windows_service_status())

    def test_remove_requires_stopped_service_and_never_stops_implicitly(self) -> None:
        self.utility.state = self.modules.win32service.SERVICE_RUNNING
        with self.assertRaises(TeamWindowsServiceError):
            remove_team_windows_service()
        self.assertEqual([], self.utility.stop_calls)
        self.assertEqual([], self.utility.remove_calls)

        self.utility.state = self.modules.win32service.SERVICE_STOPPED
        remove_team_windows_service()
        self.assertEqual([TEAM_WINDOWS_SERVICE_NAME], self.utility.remove_calls)
        self.assertEqual(
            self.modules.win32service.SERVICE_DISABLED,
            self.modules.win32service.start_type,
        )

    def test_remove_restores_start_mode_when_scm_rejects_deletion(self) -> None:
        service = self.modules.win32service
        self.utility.fail_remove = True

        with self.assertRaises(TeamWindowsServiceError) as raised:
            remove_team_windows_service()

        self.assertEqual("service_remove_failed", raised.exception.code)
        self.assertEqual(service.SERVICE_DEMAND_START, service.start_type)


class TeamWindowsServiceCLITests(unittest.TestCase):
    def test_status_and_known_failure_have_stable_exit_behavior(self) -> None:
        status = SimpleNamespace(
            service_name=TEAM_WINDOWS_SERVICE_NAME,
            state_name="running",
            win32_exit_code=0,
            service_exit_code=0,
        )
        output = io.StringIO()
        with (
            patch(
                "causure.team_windows_service_cli.get_team_windows_service_status",
                return_value=status,
            ),
            contextlib.redirect_stdout(output),
        ):
            exit_code = service_main(["status"])
        self.assertEqual(0, exit_code)
        self.assertIn("CausureTeam: running", output.getvalue())

        error = io.StringIO()
        with (
            patch(
                "causure.team_windows_service_cli.start_team_windows_service",
                side_effect=TeamWindowsServiceError("service_start_failed", "start failed"),
            ),
            contextlib.redirect_stderr(error),
        ):
            exit_code = service_main(["start"])
        self.assertEqual(2, exit_code)
        self.assertIn("service_start_failed", error.getvalue())

    def test_install_passes_manual_start_without_registering_in_test(self) -> None:
        output = io.StringIO()
        with (
            patch("causure.team_windows_service_cli.install_team_windows_service") as install,
            contextlib.redirect_stdout(output),
        ):
            exit_code = service_main(["install", r"C:\Protected\team-host.json", "--manual-start"])
        self.assertEqual(0, exit_code)
        install.assert_called_once_with(
            r"C:\Protected\team-host.json",
            automatic_start=False,
        )
        self.assertIn("manual start", output.getvalue())

    def test_recovery_status_is_machine_readable_and_redacts_values(self) -> None:
        policy = TeamWindowsServiceRecoveryPolicy(
            reset_period_seconds=900,
            actions=(
                TeamWindowsServiceRecoveryAction("restart", 120_000),
                TeamWindowsServiceRecoveryAction("none", 0),
            ),
            apply_on_non_crash_failures=True,
            reboot_message_configured=False,
            command_configured=False,
        )
        output = io.StringIO()
        with (
            patch(
                "causure.team_windows_service_cli.get_team_windows_service_recovery_policy",
                return_value=policy,
            ),
            contextlib.redirect_stdout(output),
        ):
            exit_code = service_main(["recovery-status"])

        self.assertEqual(0, exit_code)
        self.assertEqual(
            '{"service_name":"CausureTeam","reset_period_seconds":900,'
            '"actions":[{"action":"restart","delay_milliseconds":120000},'
            '{"action":"none","delay_milliseconds":0}],'
            '"apply_on_non_crash_failures":true,"reboot_message_configured":false,'
            '"command_configured":false}',
            output.getvalue().strip(),
        )


@unittest.skipUnless(sys.platform == "win32", "pywin32 service entry is Windows-only")
class TeamWindowsServiceEntryTests(unittest.TestCase):
    def _instance(self) -> Any:
        from causure.team_windows_service_entry import CausureTeamService

        instance = object.__new__(CausureTeamService)
        instance._stop_requested = threading.Event()
        instance._controller_lock = threading.RLock()
        instance._controller = None
        instance._control_failure = None
        instance.ReportServiceStatus = Mock()
        return instance

    def test_service_entry_runs_registered_controller_and_closes(self) -> None:
        import causure.team_windows_service_entry as entry

        instance = self._instance()
        controller = Mock()
        with (
            patch.object(entry, "load_registered_team_host_configuration", return_value=object()),
            patch.object(entry, "create_team_host_server", return_value=controller),
            patch.object(entry.servicemanager, "LogInfoMsg"),
            patch.object(entry.servicemanager, "LogErrorMsg") as errors,
        ):
            instance.SvcDoRun()

        controller.run.assert_called_once_with()
        controller.close.assert_called_once_with()
        errors.assert_not_called()

    def test_stop_signals_and_closes_without_logging_sensitive_exception_text(self) -> None:
        import causure.team_windows_service_entry as entry

        instance = self._instance()
        controller = Mock()
        controller.close.side_effect = RuntimeError("secret path or token")
        instance._controller = controller
        with patch.object(entry.servicemanager, "LogErrorMsg") as log_error:
            instance.SvcStop()

        self.assertTrue(instance._stop_requested.is_set())
        instance.ReportServiceStatus.assert_called_once()
        controller.close.assert_called_once_with()
        logged = log_error.call_args.args[0]
        self.assertIn("RuntimeError", logged)
        self.assertNotIn("secret path or token", logged)

    def test_service_failure_rethrows_only_sanitized_context(self) -> None:
        import causure.team_windows_service_entry as entry

        instance = self._instance()
        controller = Mock()
        controller.run.side_effect = RuntimeError("secret path or token")
        with (
            patch.object(entry, "load_registered_team_host_configuration", return_value=object()),
            patch.object(entry, "create_team_host_server", return_value=controller),
            patch.object(entry.servicemanager, "LogInfoMsg"),
            patch.object(entry.servicemanager, "LogErrorMsg") as log_error,
            self.assertRaises(RuntimeError) as raised,
        ):
            instance.SvcDoRun()

        self.assertIn("RuntimeError", str(raised.exception))
        self.assertNotIn("secret path or token", str(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertTrue(raised.exception.__suppress_context__)
        self.assertIn("RuntimeError", log_error.call_args.args[0])
        self.assertNotIn("secret path or token", log_error.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
