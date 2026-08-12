# ADR 0001: Build the evidence gate before the dashboard

- Status: accepted
- Date: 2026-07-27

## Context

The product vision includes trace import, replay, diagnosis, change recommendation, approval,
and deployment tracking. Starting with a dashboard or full agent runtime would create a broad
surface without first defining what evidence justifies an approval.

## Decision

The first release is a deterministic, zero-runtime-dependency evidence gate with a portable
JSON contract, policy thresholds, reports, and CI exit codes.

It does not execute agent code, fetch evidence, or autonomously modify a harness.

## Consequences

- The product has a usable CI boundary immediately.
- Approval logic can be tested without model or vendor variability.
- Future collectors and dashboards share one versioned contract.
- The alpha depends on upstream systems to generate trustworthy replay and evaluation
  evidence.
- Cryptographic provenance and live artifact validation remain future work.
