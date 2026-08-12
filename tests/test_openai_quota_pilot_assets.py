"""Static contract tests for the split-edge OpenAI quota pilot assets."""

from __future__ import annotations

import hashlib
import json
import re
import unittest

from tests.helpers import PROJECT_ROOT

PILOT_ROOT = PROJECT_ROOT / "deploy" / "openai-quota-pilot"
COMPOSE = PILOT_ROOT / "compose.yaml"
DOCKERFILE = PILOT_ROOT / "Dockerfile"
EDGE_DOCKERFILE = PILOT_ROOT / "Dockerfile.edge"
WORKER_CADDYFILE = PILOT_ROOT / "Caddyfile.worker"
ADMIN_CADDYFILE = PILOT_ROOT / "Caddyfile.admin"
BUILD_SCRIPT = PROJECT_ROOT / "scripts" / "build_openai_quota_pilot.ps1"
QUALIFICATION_SCRIPT = PROJECT_ROOT / "scripts" / "qualify_openai_quota_pilot.ps1"
IMAGE_LOCK = PILOT_ROOT / "images.lock.json"
PASSED_RECEIPT = (
    PROJECT_ROOT / "docs" / "qualifications" / "openai-quota-pilot-local-2026-08-09.json"
)
FAILED_RECEIPT = (
    PROJECT_ROOT / "docs" / "qualifications" / "openai-quota-pilot-local-2026-08-09-attempt-1.json"
)


def _service_block(contents: str, service: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(service)}:\n(?P<body>.*?)(?=^  [a-z][a-z0-9-]*:\n|^configs:\n)",
        contents,
    )
    if match is None:
        raise AssertionError(f"missing Compose service {service}")
    return match.group("body")


class OpenAIQuotaPilotAssetTests(unittest.TestCase):
    def test_docker_context_is_allowlisted_to_two_exact_wheels_and_the_dockerfile(self) -> None:
        lines = (PROJECT_ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()

        self.assertEqual("**", lines[0])
        self.assertIn("!dist/causure-0.4.0a18-py3-none-any.whl", lines)
        self.assertIn(
            "!build/quota-pilot/wheels/waitress-3.0.2-py3-none-any.whl",
            lines,
        )
        self.assertIn("!deploy/openai-quota-pilot/Dockerfile", lines)
        self.assertIn("!deploy/openai-quota-pilot/Dockerfile.edge", lines)
        self.assertFalse(any("state" in line or "secret" in line for line in lines))

    def test_core_image_build_is_offline_nonroot_and_hash_checks_waitress(self) -> None:
        contents = DOCKERFILE.read_text(encoding="utf-8")

        self.assertIn(
            "FROM python@sha256:9662417aace5ae7b8e2609cce472b72a8958e134ba372808abe9cc1a0c0125e6",
            contents,
        )
        self.assertIn("--no-index", contents)
        self.assertIn("--no-deps", contents)
        self.assertIn("ARG CAUSURE_WHEEL_SHA256", contents)
        self.assertIn("$CAUSURE_WHEEL_SHA256", contents)
        self.assertIn(
            "c56d67fd6e87c2ee598b76abdd4e96cfad1f24cacdea5078d382b1f9d7b5ed2e",
            contents,
        )
        self.assertIn("USER 65532:65532", contents)
        self.assertIn("PYTHONDONTWRITEBYTECODE=1", contents)
        self.assertIn("openai-quota-serve", contents)
        self.assertNotIn("curl ", contents)
        self.assertNotIn("apt-get", contents)

    def test_edge_image_removes_only_the_unneeded_low_port_file_capability(self) -> None:
        contents = EDGE_DOCKERFILE.read_text(encoding="utf-8")

        self.assertIn(
            "FROM caddy@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648",
            contents,
        )
        self.assertIn("setcap -r /usr/bin/caddy", contents)
        self.assertIn('test -z "$(getcap /usr/bin/caddy)"', contents)
        self.assertIn("USER 65532:65532", contents)
        self.assertNotIn("apk add", contents)

    def test_compose_keeps_worker_core_admin_and_egress_networks_separate(self) -> None:
        contents = COMPOSE.read_text(encoding="utf-8")
        core = _service_block(contents, "quota-core")
        worker = _service_block(contents, "worker-edge")
        admin = _service_block(contents, "admin-edge")

        self.assertIn("container_name: openai-quota-core", core)
        self.assertIn("- quota-backend", core)
        self.assertIn("- provider-egress", core)
        self.assertNotIn("quota-worker", core)
        self.assertNotIn("ports:", core)

        self.assertIn("container_name: openai-quota", worker)
        self.assertIn("- quota-worker", worker)
        self.assertIn("- quota-backend", worker)
        self.assertNotIn("provider-egress", worker)
        self.assertNotIn("ports:", worker)

        self.assertIn("container_name: openai-quota-admin", admin)
        self.assertIn("- quota-backend", admin)
        self.assertIn("- quota-admin-control", admin)
        self.assertNotIn("quota-worker", admin)
        self.assertNotIn("provider-egress", admin)
        self.assertIn('"127.0.0.1:${CAUSURE_QUOTA_ADMIN_PORT:-9443}:9443/tcp"', admin)

        self.assertRegex(
            contents,
            r"(?ms)^  quota-worker:\n.*?name: causure-quota\n.*?internal: true",
        )
        self.assertRegex(
            contents,
            r"(?ms)^  provider-egress:\n.*?internal: false",
        )
        self.assertRegex(
            contents,
            r"(?ms)^  quota-admin-control:\n.*?internal: false",
        )

    def test_every_service_is_read_only_unprivileged_and_locally_pinned(self) -> None:
        contents = COMPOSE.read_text(encoding="utf-8")
        for service in ("quota-core", "worker-edge", "admin-edge"):
            with self.subTest(service=service):
                block = _service_block(contents, service)
                self.assertIn("pull_policy: never", block)
                self.assertIn("read_only: true", block)
                self.assertIn('user: "65532:65532"', block)
                self.assertIn('cap_drop: ["ALL"]', block)
                self.assertIn('security_opt: ["no-new-privileges=true"]', block)
                self.assertIn("pids_limit:", block)
                self.assertIn("mem_limit:", block)
                self.assertIn("cpus:", block)
                self.assertNotIn("environment:", block)
                self.assertNotIn("docker.sock", block)

    def test_split_edges_expose_mutually_exclusive_routes_and_strip_proxy_identity(self) -> None:
        worker = WORKER_CADDYFILE.read_text(encoding="utf-8")
        admin = ADMIN_CADDYFILE.read_text(encoding="utf-8")

        for contents in (worker, admin):
            self.assertIn("admin off", contents)
            self.assertIn("auto_https off", contents)
            self.assertIn("protocols tls1.2 tls1.3", contents)
            self.assertIn("header_up -Forwarded", contents)
            self.assertIn("header_up -X-Forwarded-For", contents)
            self.assertIn("header_up -X-Forwarded-Proto", contents)
            self.assertIn("respond 404", contents)
            self.assertNotIn("log {", contents)

        self.assertIn("/v1/responses", worker)
        self.assertNotIn("/admin/", worker)
        self.assertIn("/admin/v1/leases*", admin)
        self.assertNotIn("/v1/responses", admin)

    def test_secret_state_has_explicit_tfvc_exclusions(self) -> None:
        contents = (PROJECT_ROOT / ".tfignore").read_text(encoding="utf-8")

        self.assertIn("\\pilot-state", contents)
        self.assertIn("\\deploy\\openai-quota-pilot\\state", contents)
        self.assertIn("*.key", contents)
        self.assertIn("*.pem", contents)

    def test_build_script_binds_the_wheel_and_disables_build_network_and_provenance(self) -> None:
        contents = BUILD_SCRIPT.read_text(encoding="utf-8")

        self.assertIn("--no-build-isolation", contents)
        self.assertIn("--no-index", contents)
        self.assertIn('"--network",', contents)
        self.assertIn('"none",', contents)
        self.assertIn('"--provenance=false",', contents)
        self.assertIn("CAUSURE_WHEEL_SHA256", contents)
        self.assertIn("setuptools 83.0.0", contents)

    def test_qualification_script_is_no_provider_and_self_cleaning(self) -> None:
        contents = QUALIFICATION_SCRIPT.read_text(encoding="utf-8")

        self.assertIn("offline-local-pilot-no-provider-request", contents)
        self.assertIn("live_api_request_performed = $false", contents)
        self.assertIn("invoice_reconciliation_performed = $false", contents)
        self.assertIn('"down",', contents)
        self.assertIn('"--volumes",', contents)
        self.assertIn("worker_cannot_reach_admin", contents)
        self.assertIn("pre_restart_lease_canceled_after_restart", contents)
        self.assertNotIn("/v1/responses',data", contents)

    def test_local_image_lock_binds_passed_and_failed_qualification_receipts(self) -> None:
        lock = json.loads(IMAGE_LOCK.read_text(encoding="utf-8"))
        validation = lock["local_validation"]
        derived = lock["local_derived_images"]
        historical = validation["historical_pre_rebrand"]

        self.assertEqual("requalification_required_after_rebrand", validation["status"])
        self.assertFalse(validation["core_image_built_without_network"])
        self.assertFalse(validation["edge_image_built_without_network"])
        self.assertFalse(validation["verified_tls_route_isolation"])
        self.assertFalse(validation["worker_direct_provider_tcp_blocked"])
        self.assertFalse(validation["lease_persisted_across_core_restart"])
        self.assertFalse(validation["live_provider_called"])
        self.assertFalse(validation["production_qualification"])
        self.assertIsNone(derived["quota_core_image_id"])
        self.assertIsNone(derived["quota_edge_image_id"])
        self.assertRegex(derived["causure_wheel_sha256"], r"^[a-f0-9]{64}$")
        self.assertFalse(derived["portable_registry_provenance_claimed"])
        self.assertEqual("0.4.0a17", historical["package_version"])

        for field, path in (
            ("passed_receipt", PASSED_RECEIPT),
            ("failed_observer_attempt_retained", FAILED_RECEIPT),
        ):
            with self.subTest(field=field):
                self.assertEqual(
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                    historical[field]["sha256"],
                )

        receipt = json.loads(PASSED_RECEIPT.read_text(encoding="utf-8"))
        self.assertEqual("passed", receipt["result"])
        self.assertEqual("offline-local-pilot-no-provider-request", receipt["scope"])
        self.assertTrue(receipt["evidence"]["network"]["direct_provider_tcp_blocked"])
        self.assertTrue(receipt["evidence"]["restart"]["pre_restart_lease_canceled_after_restart"])
        self.assertFalse(receipt["evidence"]["provider"]["live_api_request_performed"])
        self.assertTrue(receipt["cleanup"]["disposable_volume_absent"])


if __name__ == "__main__":
    unittest.main()
