"""Provision an IoT device with an mTLS identity, then let it authenticate.

Two halves, and the split between them is the point.

**The operator half** runs once, on a machine an administrator controls, against
an authenticated §27 management client. It creates the device's service account,
mints a Device certificate from the tenant's signing CA, binds the two, and
writes the private key to disk. That key is returned by exactly one call and
never again (§27.5 rule 3) — no later ``get`` has a field where it was — so
losing the response means revoking the certificate and minting another.

**The device half** runs on the device, forever after, with no password and no
management access at all. It presents the certificate and key as a §6.1 mutual
TLS identity and does nothing else privileged.

Run against a real deployment with the environment set:

    AXIAM_URL=https://axiam.example.com \\
    AXIAM_TENANT=acme \\
    AXIAM_ADMIN=admin@example.com \\
    AXIAM_ADMIN_PASSWORD=... \\
    python examples/device_mtls_provisioning.py provision sensor-42

    python examples/device_mtls_provisioning.py run sensor-42
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

from axiam_sdk import AxiamClient
from axiam_sdk.management import ConflictError, NotFoundError, ValidationError, models

BASE_URL = os.environ.get("AXIAM_URL", "https://axiam.example.com")
TENANT_SLUG = os.environ.get("AXIAM_TENANT", "acme")
ADMIN = os.environ.get("AXIAM_ADMIN", "admin@example.com")
ADMIN_PASSWORD = os.environ.get("AXIAM_ADMIN_PASSWORD", "")
ORG_CA_BUNDLE = os.environ.get("AXIAM_ORG_CA")

IDENTITY_DIR = Path(os.environ.get("AXIAM_DEVICE_DIR", "./device-identity"))
"""Where the device's certificate and private key are written, and read back."""


def _write_secret(path: Path, content: str) -> None:
    """Write ``content`` to ``path`` readable only by this user.

    The private key is written with the mode set at creation rather than
    afterwards: a `chmod` after the fact leaves a window in which the key is
    world-readable, which on a shared provisioning host is the whole exposure.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w") as handle:
        handle.write(content)


def provision(device_name: str) -> None:
    """Create the device's identity and write it to disk, once.

    Every step here is a §27 management call, and every one of them is a write
    that is issued exactly once — §27.4 rule 8 does not retry writes, because
    generating a certificate twice mints two and only one of them is the one
    written to disk.
    """
    with AxiamClient(
        base_url=BASE_URL,
        tenant_slug=TENANT_SLUG,
        custom_ca=ORG_CA_BUNDLE,
    ) as client:
        client.login(ADMIN, ADMIN_PASSWORD)

        # 1. The signing CA this tenant's device certificates chain to.
        #    `{org_id}` defaults from the client (§27.4 rule 3). `{tenant_id}`
        #    does NOT on this route: under `ca_certificates` it names the tenant
        #    being administered rather than the calling context, so it is an
        #    ordinary argument. `resolved_tenant_id()` is the UUID login decoded.
        tenant_id = client.resolved_tenant_id()
        if tenant_id is None:
            raise SystemExit("login did not resolve a tenant UUID; cannot address signing CAs")
        signing_cas = client.ca_certificates.list_signing_cas_all(tenant_id)
        active = [ca for ca in signing_cas if ca.status == "Active"]
        if not active:
            raise SystemExit(
                f"tenant {TENANT_SLUG!r} has no active signing CA; generate one with "
                f"client.ca_certificates.generate_signing_ca(...) before provisioning devices"
            )
        issuer = active[0]

        # 2. The service account the device authenticates as.
        try:
            account = client.service_accounts.create(
                models.CreateServiceAccountRequest(
                    name=device_name,
                    description=f"IoT device {device_name}, mTLS identity",
                )
            )
        except ConflictError:
            # Already provisioned. Re-minting a certificate for an existing
            # account is a decision an operator should make deliberately, so
            # this stops rather than quietly issuing a second identity.
            raise SystemExit(
                f"a service account named {device_name!r} already exists; revoke its "
                f"certificate and delete it first, or pick another name"
            ) from None

        # 3. The certificate. `private_key_pem` comes back from THIS call and no
        #    other — `certificates.get` has no field where it was.
        certificate = client.certificates.generate(
            models.CreateCertificateRequest(
                issuer_ca_id=issuer.id,
                subject=f"CN={device_name},OU=devices,O={TENANT_SLUG}",
                cert_type="Device",
                key_algorithm="Ed25519",
                validity_days=825,
            )
        )

        # 4. Write it down before doing anything else that could fail. The key
        #    is a SecretStr, so `.get_secret_value()` is the one explicit unwrap
        #    (§27.5) — printing `certificate` anywhere shows `**********`.
        _write_secret(
            IDENTITY_DIR / f"{device_name}-key.pem", certificate.private_key_pem.get_secret_value()
        )
        (IDENTITY_DIR / f"{device_name}-cert.pem").write_text(
            certificate.public_cert_pem + (certificate.chain_pem or "")
        )

        # 5. Bind the certificate to the account, so presenting it authenticates
        #    as that principal.
        client.service_accounts.bind_certificate(
            account.id, models.BindCertificate(certificate_id=certificate.id)
        )

        print(f"provisioned {device_name}")
        print(f"  service account : {account.id}")
        print(f"  certificate     : {certificate.id} ({certificate.fingerprint})")
        print(f"  valid until     : {certificate.not_after}")
        print(f"  identity written: {IDENTITY_DIR}/")


def run(device_name: str) -> None:
    """Authenticate as the device, with the identity provisioning wrote.

    No password, no management surface, no secret in the environment — the
    private key on disk *is* the credential. Presenting it never relaxes server
    verification (§6.1 rule 2): strict TLS stays fully on.
    """
    cert_path = IDENTITY_DIR / f"{device_name}-cert.pem"
    key_path = IDENTITY_DIR / f"{device_name}-key.pem"
    if not cert_path.exists() or not key_path.exists():
        raise SystemExit(f"no identity for {device_name!r} in {IDENTITY_DIR}/; provision it first")

    with AxiamClient(
        base_url=BASE_URL,
        tenant_slug=TENANT_SLUG,
        custom_ca=ORG_CA_BUNDLE,
        client_cert=cert_path.read_bytes(),
        client_key=key_path.read_bytes(),
    ) as device:
        allowed = device.can("telemetry:publish", f"device/{device_name}")
        print(f"{device_name} may publish telemetry: {allowed}")


def revoke(device_name: str) -> None:
    """Revoke the device's certificate — the decommissioning path.

    Deleting the service account alone leaves a valid certificate in the field;
    revoking the certificate is what actually stops the device authenticating.
    """
    with AxiamClient(base_url=BASE_URL, tenant_slug=TENANT_SLUG, custom_ca=ORG_CA_BUNDLE) as client:
        client.login(ADMIN, ADMIN_PASSWORD)

        accounts = [a for a in client.service_accounts.list_all() if a.name == device_name]
        if not accounts:
            raise SystemExit(f"no service account named {device_name!r}")

        for certificate in client.certificates.list_all():
            if certificate.subject.startswith(f"CN={device_name},"):
                try:
                    client.certificates.revoke(certificate.id)
                except NotFoundError:
                    continue
                print(f"revoked {certificate.id}")

        client.service_accounts.delete(accounts[0].id)
        print(f"deleted service account {accounts[0].id}")


def main() -> int:
    """Dispatch on the sub-command."""
    if len(sys.argv) != 3 or sys.argv[1] not in ("provision", "run", "revoke"):
        print(__doc__)
        return 2
    action, device_name = sys.argv[1], sys.argv[2]
    try:
        {"provision": provision, "run": run, "revoke": revoke}[action](device_name)
    except ValidationError as err:
        # A 400/422 on this surface is usually the operator's input, not a bug:
        # a subject the CA policy rejects, a validity beyond the deployment cap.
        for field in err.fields:
            print(f"  {field.field}: {field.message}", file=sys.stderr)
        print(err, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
