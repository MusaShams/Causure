"""Prepare protected local state for the split-edge OpenAI quota pilot."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import secrets
import shutil
import stat
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from importlib import metadata
from pathlib import Path

from causure.attestations import utc_timestamp
from causure.constants import (
    OPENAI_QUOTA_HOST_CONFIG_SCHEMA_VERSION,
    PACKAGE_VERSION,
)
from causure.openai_quota import (
    MAX_OPENAI_QUOTA_CONFIG_BYTES,
    OpenAIQuotaConfiguration,
    parse_openai_quota_configuration_bytes,
)
from causure.openai_quota_host import (
    MAX_OPENAI_QUOTA_HOST_SECRET_BYTES,
    OpenAIQuotaHostConfiguration,
    parse_openai_quota_host_configuration,
    render_openai_quota_host_configuration,
)

OPENAI_QUOTA_PILOT_STATE_SCHEMA_VERSION = "1.0"
OPENAI_QUOTA_PILOT_CRYPTOGRAPHY_VERSION = "50.0.0"
OPENAI_QUOTA_PILOT_PROXY_CONTAINER_NAME = "openai-quota"
OPENAI_QUOTA_PILOT_NETWORK_NAME = "causure-quota"
OPENAI_QUOTA_PILOT_WORKER_PROXY_URL = "https://openai-quota:8443/v1"
MIN_OPENAI_QUOTA_PILOT_CERTIFICATE_DAYS = 1
MAX_OPENAI_QUOTA_PILOT_CERTIFICATE_DAYS = 90


class OpenAIQuotaPilotError(ValueError):
    """Base pilot preparation error carrying a stable, non-secret code."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"OpenAI quota pilot failed [{code}]: {message}")


class OpenAIQuotaPilotDependencyError(OpenAIQuotaPilotError):
    """Raised when exact certificate-generation dependencies drift."""


@dataclass(frozen=True, slots=True)
class OpenAIQuotaPilotState:
    """Public locations and metadata for one prepared secret-bearing state directory."""

    state_directory: str
    host_configuration_path: str
    quota_configuration_path: str
    ca_certificate_path: str
    manifest_path: str
    certificate_not_after: str


def _read_stable_file(path: str | Path, *, maximum: int, description: str) -> bytes:
    source = Path(path)
    try:
        before_link = source.lstat()
        if stat.S_ISLNK(before_link.st_mode):
            raise OpenAIQuotaPilotError(
                "source_invalid",
                f"{description} cannot be a symbolic link",
            )
        before = source.stat()
        if not stat.S_ISREG(before.st_mode):
            raise OpenAIQuotaPilotError(
                "source_invalid",
                f"{description} must be a regular file",
            )
        with source.open("rb") as stream:
            data = stream.read(maximum + 1)
        after = source.stat()
        after_link = source.lstat()
    except OpenAIQuotaPilotError:
        raise
    except OSError as exc:
        raise OpenAIQuotaPilotError(
            "source_unavailable",
            f"{description} could not be read",
        ) from exc
    if (
        stat.S_ISLNK(after_link.st_mode)
        or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        or len(data) != before.st_size
    ):
        raise OpenAIQuotaPilotError(
            "source_changed",
            f"{description} changed while being read",
        )
    if not data or len(data) > maximum:
        raise OpenAIQuotaPilotError(
            "source_invalid",
            f"{description} has an invalid byte count",
        )
    return data


def _secret_bytes(path: str | Path, *, description: str) -> bytes:
    value = _read_stable_file(
        path,
        maximum=MAX_OPENAI_QUOTA_HOST_SECRET_BYTES,
        description=description,
    )
    if value.endswith(b"\r\n"):
        value = value[:-2]
    elif value.endswith(b"\n"):
        value = value[:-1]
    try:
        decoded = value.decode("ascii")
    except UnicodeDecodeError as exc:
        raise OpenAIQuotaPilotError(
            "secret_invalid",
            f"{description} must contain visible ASCII",
        ) from exc
    if not 32 <= len(decoded) <= MAX_OPENAI_QUOTA_HOST_SECRET_BYTES or any(
        not 32 <= ord(character) <= 126 for character in decoded
    ):
        raise OpenAIQuotaPilotError(
            "secret_invalid",
            f"{description} must contain 32 through {MAX_OPENAI_QUOTA_HOST_SECRET_BYTES} "
            "visible ASCII characters, with at most one trailing source newline",
        )
    return value


def _write_new_file(path: Path, content: bytes, *, mode: int) -> None:
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            written = stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if written != len(content):
            raise OSError("only a partial protected file was written")
        os.chmod(path, mode)
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _validate_now(now: datetime | None) -> datetime:
    selected = datetime.now(UTC) if now is None else now
    if not isinstance(selected, datetime) or selected.tzinfo is None:
        raise OpenAIQuotaPilotError(
            "time_invalid",
            "preparation time must be timezone-aware",
        )
    return selected.astimezone(UTC)


def _load_cryptography() -> tuple[object, object, object, object, object, object]:
    try:
        installed = metadata.version("cryptography")
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    except (ImportError, metadata.PackageNotFoundError) as exc:
        raise OpenAIQuotaPilotDependencyError(
            "dependency_unavailable",
            "pilot preparation requires the pinned 'causure[quota-pilot]' optional dependencies",
        ) from exc
    if installed != OPENAI_QUOTA_PILOT_CRYPTOGRAPHY_VERSION:
        raise OpenAIQuotaPilotDependencyError(
            "dependency_version_mismatch",
            "pilot preparation requires exact cryptography version "
            f"{OPENAI_QUOTA_PILOT_CRYPTOGRAPHY_VERSION}; found {installed}",
        )
    return x509, hashes, serialization, rsa, ExtendedKeyUsageOID, NameOID


def _pilot_certificates(
    *,
    now: datetime,
    valid_days: int,
) -> tuple[bytes, bytes, bytes, datetime]:
    x509, hashes, serialization, rsa, extended_key_usage_oid, name_oid = _load_cryptography()
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ca_name = x509.Name([x509.NameAttribute(name_oid.COMMON_NAME, "Causure Pilot Ephemeral CA")])
    leaf_name = x509.Name(
        [x509.NameAttribute(name_oid.COMMON_NAME, OPENAI_QUOTA_PILOT_PROXY_CONTAINER_NAME)]
    )
    not_before = now - timedelta(minutes=5)
    not_after = now + timedelta(days=valid_days)
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf_certificate = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(OPENAI_QUOTA_PILOT_PROXY_CONTAINER_NAME),
                    x509.DNSName("openai-quota-admin"),
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    x509.IPAddress(ipaddress.ip_address("::1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([extended_key_usage_oid.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_pem = ca_certificate.public_bytes(serialization.Encoding.PEM)
    certificate_pem = leaf_certificate.public_bytes(serialization.Encoding.PEM)
    private_key_pem = leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return ca_pem, certificate_pem, private_key_pem, not_after


def _pilot_host_configuration(quota_bytes: bytes, upstream_timeout: float) -> str:
    channel_timeout = min(3600, max(10, math.ceil(upstream_timeout) + 10))
    configuration: OpenAIQuotaHostConfiguration = parse_openai_quota_host_configuration(
        {
            "schema_version": OPENAI_QUOTA_HOST_CONFIG_SCHEMA_VERSION,
            "quota_configuration": {
                "path": "/run/configs/openai-quota.json",
                "sha256": hashlib.sha256(quota_bytes).hexdigest(),
                "byte_count": len(quota_bytes),
            },
            "database": {
                "path": "/var/lib/causure/quota.sqlite3",
                "busy_timeout_ms": 5000,
            },
            "secrets": {
                "admin_token_path": "/run/secrets/openai_quota_admin_token",
                "provider_api_key_path": "/run/secrets/openai_provider_api_key",
            },
            "server": {
                "implementation": "waitress",
                "version": "3.0.2",
                "listen_host": "0.0.0.0",
                "listen_port": 8080,
                "trusted_external_scheme": "https",
                "threads": 8,
                "connection_limit": 128,
                "backlog": 64,
                "channel_timeout_seconds": channel_timeout,
                "max_request_header_bytes": 8192,
            },
        }
    )
    return render_openai_quota_host_configuration(configuration)


def _validate_pilot_quota_configuration(quota_bytes: bytes) -> OpenAIQuotaConfiguration:
    try:
        configuration = parse_openai_quota_configuration_bytes(quota_bytes)
    except ValueError as exc:
        raise OpenAIQuotaPilotError(
            "quota_configuration_invalid",
            "quota configuration is invalid",
        ) from exc
    if (
        configuration.proxy_container_name != OPENAI_QUOTA_PILOT_PROXY_CONTAINER_NAME
        or configuration.network_name != OPENAI_QUOTA_PILOT_NETWORK_NAME
        or configuration.worker_proxy_url != OPENAI_QUOTA_PILOT_WORKER_PROXY_URL
    ):
        raise OpenAIQuotaPilotError(
            "quota_topology_mismatch",
            "quota configuration does not match the fixed pilot worker edge and network",
        )
    upstream_host = configuration.upstream_responses_url.split("/", maxsplit=3)[2]
    if upstream_host.endswith(".invalid") or any(
        model.model == "replace-with-an-exact-model-revision" for model in configuration.models
    ):
        raise OpenAIQuotaPilotError(
            "quota_configuration_non_operational",
            "the deliberately non-operational reference configuration cannot prepare a pilot",
        )
    return configuration


def prepare_openai_quota_pilot_state(
    quota_configuration_path: str | Path,
    provider_api_key_path: str | Path,
    output_directory: str | Path,
    *,
    valid_days: int = 30,
    now: datetime | None = None,
) -> OpenAIQuotaPilotState:
    """Create one new secret-bearing state directory without overwriting existing state."""

    if type(valid_days) is not int or not (
        MIN_OPENAI_QUOTA_PILOT_CERTIFICATE_DAYS
        <= valid_days
        <= MAX_OPENAI_QUOTA_PILOT_CERTIFICATE_DAYS
    ):
        raise OpenAIQuotaPilotError(
            "certificate_lifetime_invalid",
            "valid_days must be an integer from "
            f"{MIN_OPENAI_QUOTA_PILOT_CERTIFICATE_DAYS} through "
            f"{MAX_OPENAI_QUOTA_PILOT_CERTIFICATE_DAYS}",
        )
    prepared_at = _validate_now(now)
    output = Path(output_directory)
    if not output.is_absolute():
        raise OpenAIQuotaPilotError(
            "state_path_invalid",
            "pilot state directory must be an absolute path outside the source tree",
        )
    if output.exists():
        raise OpenAIQuotaPilotError(
            "state_exists",
            "pilot state directory already exists and will not be overwritten",
        )
    if not output.parent.is_dir():
        raise OpenAIQuotaPilotError(
            "state_parent_unavailable",
            "pilot state parent directory is unavailable",
        )

    quota_bytes = _read_stable_file(
        quota_configuration_path,
        maximum=MAX_OPENAI_QUOTA_CONFIG_BYTES,
        description="quota configuration",
    )
    quota_configuration = _validate_pilot_quota_configuration(quota_bytes)
    provider_key = _secret_bytes(
        provider_api_key_path,
        description="provider API key",
    )
    admin_token = secrets.token_urlsafe(48).encode("ascii")
    ca_pem, certificate_pem, private_key_pem, certificate_not_after = _pilot_certificates(
        now=prepared_at,
        valid_days=valid_days,
    )
    host_configuration = _pilot_host_configuration(
        quota_bytes,
        quota_configuration.upstream_timeout_seconds,
    ).encode("utf-8")

    staging = Path(tempfile.mkdtemp(prefix=".causure-quota-pilot-", dir=output.parent))
    completed = False
    try:
        os.chmod(staging, 0o700)
        for relative in ("config", "secrets", "tls", "trust"):
            child = staging / relative
            child.mkdir()
            os.chmod(child, 0o700)
        _write_new_file(staging / "config" / "openai-quota.json", quota_bytes, mode=0o400)
        _write_new_file(
            staging / "config" / "openai-quota-host.json",
            host_configuration,
            mode=0o400,
        )
        _write_new_file(
            staging / "secrets" / "openai-provider-api-key",
            provider_key,
            mode=0o400,
        )
        _write_new_file(
            staging / "secrets" / "openai-quota-admin-token",
            admin_token,
            mode=0o400,
        )
        _write_new_file(staging / "tls" / "quota-server.crt", certificate_pem, mode=0o444)
        _write_new_file(staging / "tls" / "quota-server.key", private_key_pem, mode=0o400)
        _write_new_file(staging / "trust" / "pilot-ca.crt", ca_pem, mode=0o444)

        manifest = {
            "schema_version": OPENAI_QUOTA_PILOT_STATE_SCHEMA_VERSION,
            "package_version": PACKAGE_VERSION,
            "prepared_at": utc_timestamp(prepared_at),
            "certificate_not_after": utc_timestamp(certificate_not_after),
            "topology": {
                "worker_proxy_url": OPENAI_QUOTA_PILOT_WORKER_PROXY_URL,
                "worker_proxy_container_name": OPENAI_QUOTA_PILOT_PROXY_CONTAINER_NAME,
                "worker_network_name": OPENAI_QUOTA_PILOT_NETWORK_NAME,
                "admin_url": "https://localhost:9443",
            },
            "quota_configuration": {
                "sha256": hashlib.sha256(quota_bytes).hexdigest(),
                "byte_count": len(quota_bytes),
            },
            "host_configuration": {
                "sha256": hashlib.sha256(host_configuration).hexdigest(),
                "byte_count": len(host_configuration),
            },
            "tls": {
                "certificate_sha256": hashlib.sha256(certificate_pem).hexdigest(),
                "ca_certificate_sha256": hashlib.sha256(ca_pem).hexdigest(),
                "ca_private_key_retained": False,
            },
            "secret_delivery": {
                "provider_api_key": "protected-file",
                "admin_token": "generated-protected-file",
                "secret_hashes_recorded": False,
            },
        }
        manifest_bytes = (
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=False) + "\n"
        ).encode("utf-8")
        _write_new_file(staging / "pilot-state.json", manifest_bytes, mode=0o400)
        os.replace(staging, output)
        completed = True
    except OSError as exc:
        raise OpenAIQuotaPilotError(
            "state_write_failed",
            "pilot state could not be written atomically",
        ) from exc
    finally:
        if not completed and staging.exists():
            shutil.rmtree(staging, ignore_errors=True)

    return OpenAIQuotaPilotState(
        state_directory=str(output),
        host_configuration_path=str(output / "config" / "openai-quota-host.json"),
        quota_configuration_path=str(output / "config" / "openai-quota.json"),
        ca_certificate_path=str(output / "trust" / "pilot-ca.crt"),
        manifest_path=str(output / "pilot-state.json"),
        certificate_not_after=utc_timestamp(certificate_not_after),
    )
