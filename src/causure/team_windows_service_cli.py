"""Administrative CLI for the optional native Windows Team service adapter."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from causure.constants import PACKAGE_VERSION
from causure.team_windows_service import (
    TEAM_WINDOWS_SERVICE_NAME,
    TeamWindowsServiceError,
    TeamWindowsServiceRecoveryPolicy,
    configure_team_windows_service,
    configure_team_windows_service_recovery_policy,
    get_team_windows_service_recovery_policy,
    get_team_windows_service_status,
    install_team_windows_service,
    remove_team_windows_service,
    start_team_windows_service,
    stop_team_windows_service,
)


def _render_recovery_policy(policy: TeamWindowsServiceRecoveryPolicy) -> str:
    return json.dumps(
        {
            "service_name": TEAM_WINDOWS_SERVICE_NAME,
            "reset_period_seconds": policy.reset_period_seconds,
            "actions": [
                {
                    "action": action.action_name,
                    "delay_milliseconds": action.delay_milliseconds,
                }
                for action in policy.actions
            ],
            "apply_on_non_crash_failures": policy.apply_on_non_crash_failures,
            "reboot_message_configured": policy.reboot_message_configured,
            "command_configured": policy.command_configured,
        },
        separators=(",", ":"),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="causure-windows-service",
        description=("Manage the fixed-name, single-host Causure Team Windows service"),
    )
    parser.add_argument("--version", action="version", version=PACKAGE_VERSION)
    commands = parser.add_subparsers(dest="command", required=True)

    install = commands.add_parser(
        "install",
        help="install the stopped service and bind an exact host configuration",
    )
    install.add_argument("configuration")
    install.add_argument(
        "--manual-start",
        action="store_true",
        help="use demand start instead of delayed automatic start",
    )

    configure = commands.add_parser(
        "configure",
        help="replace the exact host-config registration while the service is stopped",
    )
    configure.add_argument("configuration")

    commands.add_parser("start", help="start the installed service")
    commands.add_parser("stop", help="stop the running service")
    commands.add_parser("status", help="show the current SCM service state")
    commands.add_parser(
        "recovery-set",
        help="set and verify the bounded SCM recovery policy while stopped",
    )
    commands.add_parser(
        "recovery-status",
        help="show the current SCM recovery policy without command or message values",
    )
    commands.add_parser(
        "remove",
        help="remove the stopped service without deleting config, state, data, or logs",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "install":
            install_team_windows_service(
                args.configuration,
                automatic_start=not args.manual_start,
            )
            start_mode = "manual" if args.manual_start else "delayed automatic"
            print(f"Installed {TEAM_WINDOWS_SERVICE_NAME} ({start_mode} start); service is stopped")
            return 0
        if args.command == "configure":
            configure_team_windows_service(args.configuration)
            print(f"Updated the exact host-config registration for {TEAM_WINDOWS_SERVICE_NAME}")
            return 0
        if args.command == "start":
            status = start_team_windows_service()
            print(f"{status.service_name}: {status.state_name}; verify /readyz at the trusted edge")
            return 0
        if args.command == "stop":
            status = stop_team_windows_service()
            print(f"{status.service_name}: {status.state_name}")
            return 0
        if args.command == "status":
            status = get_team_windows_service_status()
            print(
                f"{status.service_name}: {status.state_name} "
                f"(win32_exit={status.win32_exit_code}, service_exit={status.service_exit_code})"
            )
            return 0
        if args.command == "recovery-set":
            policy = configure_team_windows_service_recovery_policy()
            print(_render_recovery_policy(policy))
            return 0
        if args.command == "recovery-status":
            policy = get_team_windows_service_recovery_policy()
            print(_render_recovery_policy(policy))
            return 0
        if args.command == "remove":
            remove_team_windows_service()
            print(
                f"Removed {TEAM_WINDOWS_SERVICE_NAME}; "
                "operator config, state, data, and logs remain"
            )
            return 0
        raise AssertionError(f"unsupported command: {args.command}")
    except TeamWindowsServiceError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Windows service operation interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
