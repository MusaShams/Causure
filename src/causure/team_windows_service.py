"""Native Windows service registration and exact host-configuration binding."""

from __future__ import annotations

import importlib
import json
import re
import sys
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path, PureWindowsPath
from typing import Any

from causure.team_host import (
    MAX_TEAM_HOST_CONFIG_BYTES,
    MAX_TEAM_HOST_PATH_CHARACTERS,
    TeamHostConfiguration,
    TeamHostConfigurationError,
    TeamHostDependencyError,
    load_team_host_configuration_subject,
    validate_team_host_dependencies,
)

TEAM_WINDOWS_SERVICE_DEPENDENCY_VERSION = "312"
TEAM_WINDOWS_SERVICE_NAME = "CausureTeam"
TEAM_WINDOWS_SERVICE_DISPLAY_NAME = "Causure Team Service"
TEAM_WINDOWS_SERVICE_DESCRIPTION = "Single-host Causure Team evidence and change-control service"
TEAM_WINDOWS_SERVICE_ACCOUNT = f"NT SERVICE\\{TEAM_WINDOWS_SERVICE_NAME}"
TEAM_WINDOWS_SERVICE_CLASS = "causure.team_windows_service_entry.CausureTeamService"
TEAM_WINDOWS_SERVICE_REGISTRATION_SCHEMA_VERSION = "1.0"
TEAM_WINDOWS_SERVICE_PARAMETERS_KEY = (
    rf"SYSTEM\CurrentControlSet\Services\{TEAM_WINDOWS_SERVICE_NAME}\Parameters"
)
TEAM_WINDOWS_SERVICE_REGISTRATION_VALUE = "HostConfigurationSubject"
TEAM_WINDOWS_SERVICE_START_WAIT_SECONDS = 30
TEAM_WINDOWS_SERVICE_STOP_WAIT_SECONDS = 45
TEAM_WINDOWS_SERVICE_RECOVERY_RESET_SECONDS = 900
TEAM_WINDOWS_SERVICE_RECOVERY_RESTART_DELAY_MILLISECONDS = 120_000

_SHA256 = re.compile(r"^[a-f0-9]{64}$")


class TeamWindowsServiceError(ValueError):
    """Raised with a stable code for service dependency, policy, or SCM failures."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"Windows service failed [{code}]: {message}")


@dataclass(frozen=True, slots=True)
class TeamWindowsServiceRegistration:
    schema_version: str
    configuration_path: str
    configuration_sha256: str
    configuration_byte_count: int


@dataclass(frozen=True, slots=True)
class TeamWindowsServiceStatus:
    service_name: str
    state: int
    state_name: str
    win32_exit_code: int
    service_exit_code: int


@dataclass(frozen=True, slots=True)
class TeamWindowsServiceRecoveryAction:
    action_name: str
    delay_milliseconds: int


@dataclass(frozen=True, slots=True)
class TeamWindowsServiceRecoveryPolicy:
    reset_period_seconds: int
    actions: tuple[TeamWindowsServiceRecoveryAction, ...]
    apply_on_non_crash_failures: bool
    reboot_message_configured: bool
    command_configured: bool


@dataclass(frozen=True, slots=True)
class _WindowsServiceModules:
    win32service: Any
    win32serviceutil: Any
    winreg: Any


def _load_windows_service_modules() -> _WindowsServiceModules:
    if sys.platform != "win32":
        raise TeamWindowsServiceError(
            "windows_required",
            "the native service adapter is available only on Windows",
        )
    try:
        installed = metadata.version("pywin32")
    except metadata.PackageNotFoundError as exc:
        raise TeamWindowsServiceError(
            "dependency_unavailable",
            "install the pinned 'causure[windows-service]' optional dependencies",
        ) from exc
    if installed != TEAM_WINDOWS_SERVICE_DEPENDENCY_VERSION:
        raise TeamWindowsServiceError(
            "dependency_version_mismatch",
            "the Windows service adapter requires exact pywin32 version "
            f"{TEAM_WINDOWS_SERVICE_DEPENDENCY_VERSION}; found {installed}",
        )
    try:
        return _WindowsServiceModules(
            win32service=importlib.import_module("win32service"),
            win32serviceutil=importlib.import_module("win32serviceutil"),
            winreg=importlib.import_module("winreg"),
        )
    except ImportError as exc:
        raise TeamWindowsServiceError(
            "dependency_unavailable",
            "the pinned pywin32 service modules could not be imported",
        ) from exc


def parse_team_windows_service_registration(document: Any) -> TeamWindowsServiceRegistration:
    """Parse the closed registry value that pins one exact host configuration."""

    if type(document) is not dict:
        raise TeamWindowsServiceError("registration_invalid", "registration must be an object")
    required = {
        "schema_version",
        "configuration_path",
        "configuration_sha256",
        "configuration_byte_count",
    }
    keys = set(document)
    missing = required - keys
    unknown = keys - required
    if missing:
        raise TeamWindowsServiceError(
            "registration_invalid",
            f"registration is missing field {sorted(missing)[0]!r}",
        )
    if unknown:
        raise TeamWindowsServiceError(
            "registration_invalid",
            f"registration has unknown field {sorted(unknown)[0]!r}",
        )
    if document["schema_version"] != TEAM_WINDOWS_SERVICE_REGISTRATION_SCHEMA_VERSION:
        raise TeamWindowsServiceError(
            "registration_invalid",
            "registration schema version is unsupported",
        )
    path = document["configuration_path"]
    windows_path = PureWindowsPath(path) if isinstance(path, str) else None
    if (
        not isinstance(path, str)
        or not 1 <= len(path) <= MAX_TEAM_HOST_PATH_CHARACTERS
        or any(ord(character) < 32 or ord(character) == 127 for character in path)
        or windows_path is None
        or not windows_path.is_absolute()
        or re.fullmatch(r"[A-Za-z]:", windows_path.drive) is None
    ):
        raise TeamWindowsServiceError(
            "registration_invalid",
            "configuration_path must be a bounded absolute path",
        )
    sha256 = document["configuration_sha256"]
    if not isinstance(sha256, str) or _SHA256.fullmatch(sha256) is None:
        raise TeamWindowsServiceError(
            "registration_invalid",
            "configuration_sha256 must be lowercase SHA-256",
        )
    byte_count = document["configuration_byte_count"]
    if type(byte_count) is not int or not 1 <= byte_count <= MAX_TEAM_HOST_CONFIG_BYTES:
        raise TeamWindowsServiceError(
            "registration_invalid",
            "configuration_byte_count is outside the host-config limit",
        )
    return TeamWindowsServiceRegistration(
        schema_version=TEAM_WINDOWS_SERVICE_REGISTRATION_SCHEMA_VERSION,
        configuration_path=path,
        configuration_sha256=sha256,
        configuration_byte_count=byte_count,
    )


def parse_team_windows_service_registration_text(
    value: str,
) -> TeamWindowsServiceRegistration:
    """Decode one bounded duplicate-key-rejecting registry registration value."""

    if not isinstance(value, str) or not 1 <= len(value) <= 16384:
        raise TeamWindowsServiceError(
            "registration_invalid",
            "registry registration text is missing or too large",
        )

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise TeamWindowsServiceError(
                    "registration_invalid",
                    f"registration contains duplicate field {key!r}",
                )
            result[key] = item
        return result

    try:
        document = json.loads(value, object_pairs_hook=object_pairs)
    except TeamWindowsServiceError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise TeamWindowsServiceError(
            "registration_invalid",
            "registry registration is not valid JSON",
        ) from exc
    return parse_team_windows_service_registration(document)


def render_team_windows_service_registration(
    registration: TeamWindowsServiceRegistration,
) -> str:
    """Render one validated registration as canonical compact JSON."""

    if not isinstance(registration, TeamWindowsServiceRegistration):
        raise TypeError("registration must be a TeamWindowsServiceRegistration")
    registration = parse_team_windows_service_registration(
        {
            "schema_version": registration.schema_version,
            "configuration_path": registration.configuration_path,
            "configuration_sha256": registration.configuration_sha256,
            "configuration_byte_count": registration.configuration_byte_count,
        }
    )
    return json.dumps(
        {
            "schema_version": registration.schema_version,
            "configuration_path": registration.configuration_path,
            "configuration_sha256": registration.configuration_sha256,
            "configuration_byte_count": registration.configuration_byte_count,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def prepare_team_windows_service_registration(
    configuration_path: str | Path,
) -> TeamWindowsServiceRegistration:
    """Validate dependencies and bind the exact protected host-config file."""

    if sys.platform != "win32":
        raise TeamWindowsServiceError(
            "windows_required",
            "the native service adapter is available only on Windows",
        )
    source = Path(configuration_path)
    if not source.is_absolute() or source.drive.startswith(("\\", "//")):
        raise TeamWindowsServiceError(
            "configuration_path_invalid",
            "the Windows service host configuration path must be absolute",
        )
    try:
        resolved = source.resolve(strict=True)
    except OSError as exc:
        raise TeamWindowsServiceError(
            "configuration_unavailable",
            "the Windows service host configuration is unavailable",
        ) from exc
    try:
        subject = load_team_host_configuration_subject(resolved)
        validate_team_host_dependencies(subject.configuration)
    except TeamHostConfigurationError as exc:
        raise TeamWindowsServiceError(
            "host_configuration_invalid",
            "the Team host configuration is invalid",
        ) from exc
    except TeamHostDependencyError as exc:
        raise TeamWindowsServiceError(
            "host_dependency_invalid",
            "the pinned Team host serving dependency is unavailable or incompatible",
        ) from exc
    return TeamWindowsServiceRegistration(
        schema_version=TEAM_WINDOWS_SERVICE_REGISTRATION_SCHEMA_VERSION,
        configuration_path=str(resolved),
        configuration_sha256=subject.sha256,
        configuration_byte_count=subject.byte_count,
    )


def _write_registration(
    modules: _WindowsServiceModules,
    registration: TeamWindowsServiceRegistration,
) -> None:
    winreg = modules.winreg
    try:
        key = winreg.CreateKeyEx(
            winreg.HKEY_LOCAL_MACHINE,
            TEAM_WINDOWS_SERVICE_PARAMETERS_KEY,
            0,
            winreg.KEY_SET_VALUE,
        )
        try:
            winreg.SetValueEx(
                key,
                TEAM_WINDOWS_SERVICE_REGISTRATION_VALUE,
                0,
                winreg.REG_SZ,
                render_team_windows_service_registration(registration),
            )
        finally:
            winreg.CloseKey(key)
    except OSError as exc:
        raise TeamWindowsServiceError(
            "registration_write_failed",
            "the protected Windows service registration could not be written",
        ) from exc


def _read_registration(
    modules: _WindowsServiceModules,
) -> TeamWindowsServiceRegistration:
    winreg = modules.winreg
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            TEAM_WINDOWS_SERVICE_PARAMETERS_KEY,
            0,
            winreg.KEY_READ,
        )
        try:
            value, value_type = winreg.QueryValueEx(
                key,
                TEAM_WINDOWS_SERVICE_REGISTRATION_VALUE,
            )
        finally:
            winreg.CloseKey(key)
    except OSError as exc:
        raise TeamWindowsServiceError(
            "registration_unavailable",
            "the protected Windows service registration could not be read",
        ) from exc
    if value_type != winreg.REG_SZ or not isinstance(value, str):
        raise TeamWindowsServiceError(
            "registration_invalid",
            "the protected Windows service registration has the wrong registry type",
        )
    return parse_team_windows_service_registration_text(value)


def load_registered_team_host_configuration() -> TeamHostConfiguration:
    """Load the SCM-bound host configuration only when its exact subject still matches."""

    modules = _load_windows_service_modules()
    registration = _read_registration(modules)
    try:
        subject = load_team_host_configuration_subject(registration.configuration_path)
    except TeamHostConfigurationError as exc:
        raise TeamWindowsServiceError(
            "host_configuration_invalid",
            "the registered Team host configuration is unavailable or invalid",
        ) from exc
    if (
        subject.sha256 != registration.configuration_sha256
        or subject.byte_count != registration.configuration_byte_count
    ):
        raise TeamWindowsServiceError(
            "configuration_subject_mismatch",
            "the registered Team host configuration bytes have changed",
        )
    try:
        validate_team_host_dependencies(subject.configuration)
    except TeamHostDependencyError as exc:
        raise TeamWindowsServiceError(
            "host_dependency_invalid",
            "the pinned Team host serving dependency is unavailable or incompatible",
        ) from exc
    return subject.configuration


def _enable_service_sid(modules: _WindowsServiceModules) -> None:
    service = modules.win32service
    manager = service.OpenSCManager(None, None, service.SC_MANAGER_CONNECT)
    try:
        handle = service.OpenService(
            manager,
            TEAM_WINDOWS_SERVICE_NAME,
            service.SERVICE_CHANGE_CONFIG,
        )
        try:
            service.ChangeServiceConfig2(
                handle,
                service.SERVICE_CONFIG_SERVICE_SID_INFO,
                service.SERVICE_SID_TYPE_UNRESTRICTED,
            )
        finally:
            service.CloseServiceHandle(handle)
    finally:
        service.CloseServiceHandle(manager)


def _open_service_handle(modules: _WindowsServiceModules, access: int) -> tuple[Any, Any]:
    service = modules.win32service
    manager = service.OpenSCManager(None, None, service.SC_MANAGER_CONNECT)
    try:
        handle = service.OpenService(manager, TEAM_WINDOWS_SERVICE_NAME, access)
    except BaseException:
        service.CloseServiceHandle(manager)
        raise
    return manager, handle


def _close_service_handle(
    modules: _WindowsServiceModules,
    manager: Any,
    handle: Any,
) -> None:
    try:
        modules.win32service.CloseServiceHandle(handle)
    finally:
        modules.win32service.CloseServiceHandle(manager)


def _recovery_action_names(service: Any) -> dict[int, str]:
    return {
        service.SC_ACTION_NONE: "none",
        service.SC_ACTION_RESTART: "restart",
        service.SC_ACTION_REBOOT: "reboot",
        service.SC_ACTION_RUN_COMMAND: "run_command",
    }


def _parse_recovery_policy(
    modules: _WindowsServiceModules,
    failure_actions: Any,
    apply_on_non_crash_failures: Any,
) -> TeamWindowsServiceRecoveryPolicy:
    if type(failure_actions) is not dict:
        raise TeamWindowsServiceError(
            "service_recovery_invalid",
            "Windows returned invalid service failure actions",
        )
    required = {"ResetPeriod", "RebootMsg", "Command", "Actions"}
    if set(failure_actions) != required:
        raise TeamWindowsServiceError(
            "service_recovery_invalid",
            "Windows returned incomplete service failure actions",
        )
    reset_period = failure_actions["ResetPeriod"]
    reboot_message = failure_actions["RebootMsg"]
    command = failure_actions["Command"]
    raw_actions = failure_actions["Actions"]
    if type(reset_period) is not int or not 0 <= reset_period <= 0xFFFFFFFF:
        raise TeamWindowsServiceError(
            "service_recovery_invalid",
            "Windows returned an invalid failure reset period",
        )
    if reboot_message is not None and not isinstance(reboot_message, str):
        raise TeamWindowsServiceError(
            "service_recovery_invalid",
            "Windows returned an invalid recovery reboot-message state",
        )
    if command is not None and not isinstance(command, str):
        raise TeamWindowsServiceError(
            "service_recovery_invalid",
            "Windows returned an invalid recovery command state",
        )
    if not isinstance(raw_actions, (tuple, list)) or len(raw_actions) > 64:
        raise TeamWindowsServiceError(
            "service_recovery_invalid",
            "Windows returned an invalid recovery action sequence",
        )
    action_names = _recovery_action_names(modules.win32service)
    actions: list[TeamWindowsServiceRecoveryAction] = []
    for raw_action in raw_actions:
        if not isinstance(raw_action, (tuple, list)) or len(raw_action) != 2:
            raise TeamWindowsServiceError(
                "service_recovery_invalid",
                "Windows returned an invalid recovery action",
            )
        action_type, delay = raw_action
        if (
            type(action_type) is not int
            or action_type not in action_names
            or type(delay) is not int
            or not 0 <= delay <= 0xFFFFFFFF
        ):
            raise TeamWindowsServiceError(
                "service_recovery_invalid",
                "Windows returned an unsupported recovery action",
            )
        actions.append(
            TeamWindowsServiceRecoveryAction(
                action_name=action_names[action_type],
                delay_milliseconds=delay,
            )
        )
    if type(apply_on_non_crash_failures) is bool:
        apply_on_non_crash = apply_on_non_crash_failures
    elif type(apply_on_non_crash_failures) is int and apply_on_non_crash_failures in (0, 1):
        apply_on_non_crash = bool(apply_on_non_crash_failures)
    else:
        raise TeamWindowsServiceError(
            "service_recovery_invalid",
            "Windows returned an invalid non-crash failure flag",
        )
    return TeamWindowsServiceRecoveryPolicy(
        reset_period_seconds=reset_period,
        actions=tuple(actions),
        apply_on_non_crash_failures=apply_on_non_crash,
        reboot_message_configured=bool(reboot_message),
        command_configured=bool(command),
    )


def _expected_recovery_policy() -> TeamWindowsServiceRecoveryPolicy:
    return TeamWindowsServiceRecoveryPolicy(
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


def _desired_recovery_failure_actions(modules: _WindowsServiceModules) -> dict[str, Any]:
    service = modules.win32service
    return {
        "ResetPeriod": TEAM_WINDOWS_SERVICE_RECOVERY_RESET_SECONDS,
        "RebootMsg": None,
        "Command": None,
        "Actions": (
            (
                service.SC_ACTION_RESTART,
                TEAM_WINDOWS_SERVICE_RECOVERY_RESTART_DELAY_MILLISECONDS,
            ),
            (service.SC_ACTION_NONE, 0),
        ),
    }


def _query_recovery_policy(
    modules: _WindowsServiceModules,
    handle: Any,
) -> tuple[TeamWindowsServiceRecoveryPolicy, dict[str, Any], bool]:
    service = modules.win32service
    failure_actions = service.QueryServiceConfig2(
        handle,
        service.SERVICE_CONFIG_FAILURE_ACTIONS,
    )
    apply_on_non_crash = service.QueryServiceConfig2(
        handle,
        service.SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
    )
    policy = _parse_recovery_policy(modules, failure_actions, apply_on_non_crash)
    return policy, failure_actions, bool(apply_on_non_crash)


def _configure_recovery_policy(
    modules: _WindowsServiceModules,
) -> TeamWindowsServiceRecoveryPolicy:
    service = modules.win32service
    access = service.SERVICE_QUERY_CONFIG | service.SERVICE_CHANGE_CONFIG | service.SERVICE_START
    try:
        manager, handle = _open_service_handle(modules, access)
    except Exception as exc:
        raise TeamWindowsServiceError(
            "service_recovery_open_failed",
            "the Windows service recovery configuration could not be opened",
        ) from exc
    try:
        try:
            _, previous_actions, previous_flag = _query_recovery_policy(modules, handle)
        except TeamWindowsServiceError:
            raise
        except Exception as exc:
            raise TeamWindowsServiceError(
                "service_recovery_status_failed",
                "the Windows service recovery configuration could not be read",
            ) from exc
        changed = False
        try:
            service.ChangeServiceConfig2(
                handle,
                service.SERVICE_CONFIG_FAILURE_ACTIONS,
                _desired_recovery_failure_actions(modules),
            )
            changed = True
            service.ChangeServiceConfig2(
                handle,
                service.SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
                True,
            )
            configured, _, _ = _query_recovery_policy(modules, handle)
            if configured != _expected_recovery_policy():
                raise TeamWindowsServiceError(
                    "service_recovery_verification_failed",
                    "Windows did not retain the exact bounded recovery policy",
                )
            return configured
        except BaseException as exc:
            if changed:
                try:
                    service.ChangeServiceConfig2(
                        handle,
                        service.SERVICE_CONFIG_FAILURE_ACTIONS,
                        previous_actions,
                    )
                    service.ChangeServiceConfig2(
                        handle,
                        service.SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
                        previous_flag,
                    )
                except Exception as rollback_exc:
                    raise TeamWindowsServiceError(
                        "service_recovery_rollback_failed",
                        "recovery setup failed and its previous configuration could not "
                        "be restored",
                    ) from rollback_exc
            if isinstance(exc, (KeyboardInterrupt, SystemExit, TeamWindowsServiceError)):
                raise
            raise TeamWindowsServiceError(
                "service_recovery_configure_failed",
                "Windows rejected the bounded service recovery policy",
            ) from exc
    finally:
        _close_service_handle(modules, manager, handle)


def get_team_windows_service_recovery_policy() -> TeamWindowsServiceRecoveryPolicy:
    """Return the fixed-name service's current SCM recovery policy without secret values."""

    modules = _load_windows_service_modules()
    service = modules.win32service
    try:
        manager, handle = _open_service_handle(modules, service.SERVICE_QUERY_CONFIG)
    except Exception as exc:
        raise TeamWindowsServiceError(
            "service_recovery_open_failed",
            "the Windows service recovery configuration could not be opened",
        ) from exc
    try:
        try:
            policy, _, _ = _query_recovery_policy(modules, handle)
            return policy
        except TeamWindowsServiceError:
            raise
        except Exception as exc:
            raise TeamWindowsServiceError(
                "service_recovery_status_failed",
                "the Windows service recovery configuration could not be read",
            ) from exc
    finally:
        _close_service_handle(modules, manager, handle)


def configure_team_windows_service_recovery_policy() -> TeamWindowsServiceRecoveryPolicy:
    """Set and verify the bounded recovery policy while the service is stopped."""

    modules = _load_windows_service_modules()
    status = get_team_windows_service_status()
    if status.state != modules.win32service.SERVICE_STOPPED:
        raise TeamWindowsServiceError(
            "service_not_stopped",
            "stop the Windows service before changing its recovery policy",
        )
    return _configure_recovery_policy(modules)


def install_team_windows_service(
    configuration_path: str | Path,
    *,
    automatic_start: bool = True,
) -> TeamWindowsServiceRegistration:
    """Install the fixed-name service under its passwordless virtual service account."""

    if type(automatic_start) is not bool:
        raise TypeError("automatic_start must be a boolean")
    registration = prepare_team_windows_service_registration(configuration_path)
    modules = _load_windows_service_modules()
    service = modules.win32service
    utility = modules.win32serviceutil
    try:
        utility.InstallService(
            TEAM_WINDOWS_SERVICE_CLASS,
            TEAM_WINDOWS_SERVICE_NAME,
            TEAM_WINDOWS_SERVICE_DISPLAY_NAME,
            startType=(
                service.SERVICE_AUTO_START if automatic_start else service.SERVICE_DEMAND_START
            ),
            userName=TEAM_WINDOWS_SERVICE_ACCOUNT,
            password=None,
            description=TEAM_WINDOWS_SERVICE_DESCRIPTION,
            delayedstart=automatic_start,
        )
    except Exception as exc:
        raise TeamWindowsServiceError(
            "service_install_failed",
            "Windows Service Control Manager rejected the installation",
        ) from exc
    try:
        _enable_service_sid(modules)
        _configure_recovery_policy(modules)
        _write_registration(modules, registration)
    except BaseException as exc:
        try:
            utility.RemoveService(TEAM_WINDOWS_SERVICE_NAME)
        except Exception:
            raise TeamWindowsServiceError(
                "service_install_rollback_failed",
                "service setup failed and the partial service could not be removed",
            ) from exc
        if isinstance(exc, (KeyboardInterrupt, SystemExit, TeamWindowsServiceError)):
            raise
        raise TeamWindowsServiceError(
            "service_setup_failed",
            "Windows rejected service SID or protected registration setup",
        ) from exc
    return registration


def _status_from_raw(
    modules: _WindowsServiceModules,
    raw_status: Any,
) -> TeamWindowsServiceStatus:
    if not isinstance(raw_status, tuple) or len(raw_status) < 5:
        raise TeamWindowsServiceError(
            "service_status_invalid",
            "Windows returned an invalid service status",
        )
    service = modules.win32service
    states = {
        service.SERVICE_STOPPED: "stopped",
        service.SERVICE_START_PENDING: "start_pending",
        service.SERVICE_STOP_PENDING: "stop_pending",
        service.SERVICE_RUNNING: "running",
        service.SERVICE_CONTINUE_PENDING: "continue_pending",
        service.SERVICE_PAUSE_PENDING: "pause_pending",
        service.SERVICE_PAUSED: "paused",
    }
    state = raw_status[1]
    win32_exit_code = raw_status[3]
    service_exit_code = raw_status[4]
    if (
        type(state) is not int
        or state not in states
        or type(win32_exit_code) is not int
        or type(service_exit_code) is not int
    ):
        raise TeamWindowsServiceError(
            "service_status_invalid",
            "Windows returned an unsupported service status",
        )
    return TeamWindowsServiceStatus(
        service_name=TEAM_WINDOWS_SERVICE_NAME,
        state=state,
        state_name=states[state],
        win32_exit_code=win32_exit_code,
        service_exit_code=service_exit_code,
    )


def get_team_windows_service_status() -> TeamWindowsServiceStatus:
    """Return the current fixed-name SCM service state."""

    modules = _load_windows_service_modules()
    try:
        raw = modules.win32serviceutil.QueryServiceStatus(TEAM_WINDOWS_SERVICE_NAME)
    except Exception as exc:
        raise TeamWindowsServiceError(
            "service_status_failed",
            "the Windows service status could not be read",
        ) from exc
    return _status_from_raw(modules, raw)


def configure_team_windows_service(
    configuration_path: str | Path,
) -> TeamWindowsServiceRegistration:
    """Atomically replace the exact config registration while the service is stopped."""

    modules = _load_windows_service_modules()
    status = get_team_windows_service_status()
    if status.state != modules.win32service.SERVICE_STOPPED:
        raise TeamWindowsServiceError(
            "service_not_stopped",
            "stop the Windows service before changing its host configuration subject",
        )
    registration = prepare_team_windows_service_registration(configuration_path)
    _write_registration(modules, registration)
    return registration


def start_team_windows_service(
    *,
    wait_seconds: int = TEAM_WINDOWS_SERVICE_START_WAIT_SECONDS,
) -> TeamWindowsServiceStatus:
    """Start the service and wait for its SCM running state."""

    if type(wait_seconds) is not int or not 1 <= wait_seconds <= 300:
        raise ValueError("wait_seconds must be an integer from 1 through 300")
    modules = _load_windows_service_modules()
    utility = modules.win32serviceutil
    status = get_team_windows_service_status()
    if status.state == modules.win32service.SERVICE_RUNNING:
        return status
    if status.state != modules.win32service.SERVICE_STOPPED:
        raise TeamWindowsServiceError(
            "service_state_invalid",
            "the Windows service is not in a startable state",
        )
    try:
        utility.StartService(TEAM_WINDOWS_SERVICE_NAME)
        utility.WaitForServiceStatus(
            TEAM_WINDOWS_SERVICE_NAME,
            modules.win32service.SERVICE_RUNNING,
            wait_seconds,
        )
    except Exception as exc:
        raise TeamWindowsServiceError(
            "service_start_failed",
            "the Windows service did not reach its SCM running state",
        ) from exc
    return get_team_windows_service_status()


def stop_team_windows_service(
    *,
    wait_seconds: int = TEAM_WINDOWS_SERVICE_STOP_WAIT_SECONDS,
) -> TeamWindowsServiceStatus:
    """Request service stop and wait for the SCM stopped state."""

    if type(wait_seconds) is not int or not 1 <= wait_seconds <= 300:
        raise ValueError("wait_seconds must be an integer from 1 through 300")
    modules = _load_windows_service_modules()
    utility = modules.win32serviceutil
    status = get_team_windows_service_status()
    if status.state == modules.win32service.SERVICE_STOPPED:
        return status
    if status.state != modules.win32service.SERVICE_RUNNING:
        raise TeamWindowsServiceError(
            "service_state_invalid",
            "the Windows service is not in a stoppable state",
        )
    try:
        utility.StopService(TEAM_WINDOWS_SERVICE_NAME)
        utility.WaitForServiceStatus(
            TEAM_WINDOWS_SERVICE_NAME,
            modules.win32service.SERVICE_STOPPED,
            wait_seconds,
        )
    except Exception as exc:
        raise TeamWindowsServiceError(
            "service_stop_failed",
            "the Windows service did not reach its stopped state",
        ) from exc
    return get_team_windows_service_status()


def remove_team_windows_service() -> None:
    """Disable and remove a stopped service without deleting operator data or config."""

    modules = _load_windows_service_modules()
    status = get_team_windows_service_status()
    if status.state != modules.win32service.SERVICE_STOPPED:
        raise TeamWindowsServiceError(
            "service_not_stopped",
            "stop the Windows service before removing its SCM registration",
        )
    service = modules.win32service
    access = service.SERVICE_QUERY_CONFIG | service.SERVICE_CHANGE_CONFIG
    try:
        manager, handle = _open_service_handle(modules, access)
        try:
            previous_start_type = service.QueryServiceConfig(handle)[1]
            service.ChangeServiceConfig(
                handle,
                service.SERVICE_NO_CHANGE,
                service.SERVICE_DISABLED,
                service.SERVICE_NO_CHANGE,
                None,
                None,
                False,
                None,
                None,
                None,
                None,
            )
        finally:
            _close_service_handle(modules, manager, handle)
    except Exception as exc:
        raise TeamWindowsServiceError(
            "service_disable_failed",
            "the stopped Windows service could not be disabled before removal",
        ) from exc
    try:
        modules.win32serviceutil.RemoveService(TEAM_WINDOWS_SERVICE_NAME)
    except Exception as exc:
        try:
            manager, handle = _open_service_handle(modules, service.SERVICE_CHANGE_CONFIG)
            try:
                service.ChangeServiceConfig(
                    handle,
                    service.SERVICE_NO_CHANGE,
                    previous_start_type,
                    service.SERVICE_NO_CHANGE,
                    None,
                    None,
                    False,
                    None,
                    None,
                    None,
                    None,
                )
            finally:
                _close_service_handle(modules, manager, handle)
        except Exception as rollback_exc:
            raise TeamWindowsServiceError(
                "service_remove_rollback_failed",
                "service removal failed and its previous start mode could not be restored",
            ) from rollback_exc
        raise TeamWindowsServiceError(
            "service_remove_failed",
            "Windows Service Control Manager rejected service removal",
        ) from exc
