"""Read-modify-write for the ``replace`` updates (CONTRACT §27.4 rule 5).

A replacement resets every member it leaves out to its default, so the safe way
to change one field is: read, convert the read into the replacement body, change
the field, send the whole body back. These functions are the conversion. Each
carries every member of the read over -- and leaves the **write-only secret
absent**, which the server reads as "keep the stored one" (unless the write
moves the connection the secret is bound to; see each operation's notes). The
SDK holds no copy of any secret, so it has none to put there.

Hand-written, not generated: which member is write-only, and what absent means
for it, is a rule of each section, not a fact of the schema.
"""

from __future__ import annotations

from axiam_sdk.management import models

__all__ = ["set_directory_config"]


def set_directory_config(config: models.DirectoryConfig) -> models.SetDirectoryConfig:
    """``directory.get``'s result as a ``directory.set`` body (CONTRACT §30.2).

    ``bind_secret`` is left unset: absent keeps the stored secret -- unless the
    write changes ``url``, ``start_tls``, ``bind_dn`` or ``trust_anchors_pem``,
    which requires entering it again (§30.3 rule 2).
    """
    return models.SetDirectoryConfig(
        base_dn=config.base_dn,
        bind_dn=config.bind_dn,
        enabled=config.enabled,
        group_base_dn=config.group_base_dn,
        group_filter=config.group_filter,
        group_mappings=list(config.group_mappings),
        group_member_attribute=config.group_member_attribute,
        group_nesting_depth=config.group_nesting_depth,
        jit_provisioning=config.jit_provisioning,
        kind=config.kind,
        start_tls=config.start_tls,
        sync_interval_secs=config.sync_interval_secs,
        trust_anchors_pem=list(config.trust_anchors_pem),
        url=config.url,
        user_attribute_map=config.user_attribute_map,
        user_filter=config.user_filter,
    )
