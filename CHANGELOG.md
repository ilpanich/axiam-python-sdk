# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-alpha11] - 2026-07-18

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha10.

## [1.0.0-alpha10] - 2026-07-18

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha9.

## [Unreleased]

### Added

- Client-certificate / mutual-TLS (mTLS) support (CONTRACT.md §6.1):
  `AxiamClient` and `AsyncAxiamClient` gained additive `client_cert=` /
  `client_key=` parameters (PEM certificate chain + PEM private key, each
  `str` or `bytes`), applied to both the REST (httpx `SSLContext`) and gRPC
  (`grpc.ssl_channel_credentials`) transports. The gRPC authorization clients
  and `build_channel_credentials` accept the same parameters. The two must be
  supplied together (otherwise a construction-time `ValueError`), a non-PEM
  value is rejected, and presenting a client certificate never relaxes strict
  server verification (§6). The private key is secret material — never logged,
  exposed via a getter, or shown in `repr` (§6.1 rule 3 / §7). Conformance
  statement updated to "§1–§11 (including §6.1 mTLS)".

## [1.0.0-alpha2] - 2026-07-16

### Added

- Declarative authorization helpers (CONTRACT.md §11): `require_access` /
  `require_role` for FastAPI (`axiam_sdk.fastapi`, async, takes
  `AsyncAxiamClient`) and Django (`axiam_sdk.django.decorators`, new module,
  sync `AxiamClient` with async-view support). Both compose strictly on top
  of the existing §10 authentication guards, check the authenticated
  request's caller (`subject_id`) rather than the SDK client's own identity,
  and fail closed (503) on a transport failure while calling the authz
  endpoint. `AxiamClient.check_access`/`AsyncAxiamClient.check_access` gained
  an additive `subject_id` keyword argument (CONTRACT.md §11.2) alongside
  their unchanged existing signatures.
- Conformance statement updated to CONTRACT.md §1–§11.

## [1.0.0-alpha] - 2026-07-15

First alpha release of the official Python client SDK for AXIAM. This is an
early, pre-production preview published to PyPI for evaluation and feedback —
the public API may still change before the beta and stable releases.

> Distributed on PyPI as `1.0.0a1` (the PEP 440 spelling of `1.0.0-alpha`).

### Added

- REST client covering the AXIAM API surface (authentication, authorization
  checks, tenant/user/role/resource management).
- gRPC client for low-latency authorization checks (generated stubs shipped in
  the package; no `protoc` needed by consumers).
- FastAPI and Django integration helpers for guarding application routes.
- Strict TLS by default with no certificate-verification bypass surface.
- Fully type-annotated (`mypy --strict`) with a 100%-documented public API.
- Runnable examples for the common authentication and authorization flows.

[1.0.0-alpha]: https://github.com/ilpanich/axiam-python-sdk/releases/tag/v1.0.0-alpha
