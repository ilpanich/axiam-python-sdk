# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
