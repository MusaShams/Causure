"""pywin32 service-process entry point; imported by PythonService.exe only."""

from __future__ import annotations

import re
import threading
from typing import Any

import servicemanager
import win32service
import win32serviceutil

from causure.team_host import TeamHostServer, create_team_host_server
from causure.team_windows_service import (
    TEAM_WINDOWS_SERVICE_DISPLAY_NAME,
    TEAM_WINDOWS_SERVICE_NAME,
    load_registered_team_host_configuration,
)

_SAFE_ERROR_CODE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
_STOP_WAIT_HINT_MS = 45000


def _event_error_code(exc: BaseException) -> str:
    candidate = getattr(exc, "code", None)
    if isinstance(candidate, str) and _SAFE_ERROR_CODE.fullmatch(candidate) is not None:
        return candidate
    name = type(exc).__name__
    if _SAFE_ERROR_CODE.fullmatch(name) is not None:
        return name
    return "service_failure"


class _ServiceProcessFailure(RuntimeError):
    """Sanitized failure propagated to PythonService.exe for non-zero service exit."""


class CausureTeamService(win32serviceutil.ServiceFramework):
    """Run one exact-config Team host under Windows Service Control Manager."""

    _svc_name_ = TEAM_WINDOWS_SERVICE_NAME
    _svc_display_name_ = TEAM_WINDOWS_SERVICE_DISPLAY_NAME

    def __init__(self, args: Any) -> None:
        super().__init__(args)
        self._stop_requested = threading.Event()
        self._controller_lock = threading.RLock()
        self._controller: TeamHostServer | None = None
        self._control_failure: BaseException | None = None

    def SvcStop(self) -> None:
        self.ReportServiceStatus(
            win32service.SERVICE_STOP_PENDING,
            waitHint=_STOP_WAIT_HINT_MS,
        )
        self._stop_requested.set()
        with self._controller_lock:
            controller = self._controller
            if controller is not None:
                try:
                    controller.close()
                except BaseException as exc:
                    self._control_failure = exc
                    servicemanager.LogErrorMsg(
                        f"Causure Team service shutdown failed [{_event_error_code(exc)}]"
                    )

    def SvcShutdown(self) -> None:
        self.SvcStop()

    def SvcDoRun(self) -> None:
        controller: TeamHostServer | None = None
        failure: BaseException | None = None
        servicemanager.LogInfoMsg("Causure Team service startup requested")
        try:
            configuration = load_registered_team_host_configuration()
            controller = create_team_host_server(configuration)
            with self._controller_lock:
                self._controller = controller
                stop_requested = self._stop_requested.is_set()
            if stop_requested:
                controller.close()
            else:
                servicemanager.LogInfoMsg("Causure Team service loopback listener is ready")
                controller.run()
        except BaseException as exc:
            failure = exc
        finally:
            with self._controller_lock:
                self._controller = None
                control_failure = self._control_failure
            if controller is not None:
                try:
                    controller.close()
                except BaseException as exc:
                    if failure is None:
                        failure = exc
            if failure is None and control_failure is not None:
                failure = control_failure
            servicemanager.LogInfoMsg("Causure Team service stopped")
        if failure is not None:
            code = _event_error_code(failure)
            servicemanager.LogErrorMsg(f"Causure Team service failed [{code}]")
            raise _ServiceProcessFailure(f"Causure Team service failed [{code}]") from None
