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

from collections.abc import Mapping
from typing import Any

from axiam_sdk.management import models
from axiam_sdk.management._errors import local_refusal

__all__ = [
    "saml_service_provider_input",
    "scim_target_input",
    "set_directory_config",
    "ssf_stream_edit",
    "ssf_stream_input",
]


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


def saml_service_provider_input(
    sp: models.SamlServiceProvider,
) -> models.SamlServiceProviderInput:
    """``saml.get_service_provider``'s result as a
    ``saml.update_service_provider`` body (CONTRACT §29.2).

    Every member is carried over, so changing one and sending the body back
    preserves the rest -- an omitted member would take its **default**, not its
    stored value. ``entity_id`` is carried unchanged: it is immutable (§29.3
    rule 3). No member is secret on this namespace (§29.5).
    """
    return models.SamlServiceProviderInput(
        acs_urls=[a.model_copy() for a in sp.acs_urls],
        allow_idp_initiated=sp.allow_idp_initiated,
        allowed_groups=list(sp.allowed_groups),
        attribute_mappings=[m.model_copy() for m in sp.attribute_mappings],
        display_name=sp.display_name,
        enabled=sp.enabled,
        encrypt_assertions=sp.encrypt_assertions,
        entity_id=sp.entity_id,
        name_id_format=sp.name_id_format,
        sign_responses=sp.sign_responses,
        slo_binding=sp.slo_binding,
        slo_url=sp.slo_url,
        sp_encryption_cert_pem=sp.sp_encryption_cert_pem,
        sp_signing_cert_pem=sp.sp_signing_cert_pem,
        want_authn_requests_signed=sp.want_authn_requests_signed,
    )


def scim_target_input(target: models.ScimTargetResponse) -> models.ScimTargetInput:
    """``scim_targets.get``'s result as a ``scim_targets.update`` body
    (CONTRACT §31.2).

    ``credential`` is left unset: absent keeps the stored one -- unless the write
    changes ``base_url`` (of either kind), ``auth.token_url`` or ``auth.type``,
    which requires sending it again (§31.3 rule 2). A target whose ``auth`` or
    ``scope`` arm this SDK does not know converts, but cannot be sent:
    ``to_wire`` refuses an unknown arm (§31.2).

    ``expected_updated_at`` is the ``updated_at`` that was read (§31.3 rule 4,
    contract 1.60): the update then lands only if nobody has written the target
    since, and is otherwise ``409`` -- reload and retry. Unset it to fall back
    to last-writer-wins.
    """
    return models.ScimTargetInput(
        auth=target.auth.model_copy(),
        base_url=target.base_url,
        deprovision=target.deprovision,
        enabled=target.enabled,
        expected_updated_at=target.updated_at,
        name=target.name,
        push_groups=target.push_groups,
        scope=target.scope.model_copy(),
        user_name_from=target.user_name_from,
    )


def ssf_stream_input(stream: models.SsfStream) -> models.SsfStreamInput:
    """``ssf.get_stream``'s result as an ``ssf.update_stream`` body (CONTRACT
    §32.2).

    ``authorization_header`` and ``clear_authorization_header`` are left unset:
    absent keeps the stored header -- unless the update moves ``endpoint_url``
    to another scheme, host or port while one is stored, which requires sending
    it again or clearing it (§32.3 rule 5). The read-only members
    (``events_delivered``, ``authorization_header_set``, the transmitter state)
    have no place on the input and are not carried.

    ``events_requested`` is always carried as read -- ``[]`` stays ``[]``, because
    omitting it would reset a receiver's narrowing to every allowed event -- and
    ``expected_updated_at`` is the ``updated_at`` that was read, verbatim (§32.2,
    contract 1.61): the update then lands only if nobody has written the stream
    since (the receiver's pause or narrowing included), and is otherwise ``409``
    -- reload and retry. Unset it to fall back to the server's
    version-at-request.

    **The caller's duty (CONTRACT §32.2, contract 1.62).** This converter cannot
    know that you will lower ``events_allowed``, so the cut is yours: an edit that
    lowers the ceiling must cut ``events_requested`` to the new ``events_allowed``
    before the update is sent, or the server refuses it ``400`` (a list outside
    ``events_allowed``). Do **not** drop ``events_requested`` to get out of the
    cut: *absent* **resets** the stream to every event of ``events_allowed``,
    widening a narrowing the receiver made, so AXIAM then sends the receiver more
    events about your tenant's users than it asked for. The three meanings of
    ``events_requested`` -- absent resets, ``[]`` is none, a list is stored as given
    and refused outside ``events_allowed`` -- are stated at
    :meth:`~axiam_sdk.management.ops.ssf.SsfApi.update_stream`. A stream written
    since the read answers ``409`` (:class:`~axiam_sdk.management.ConflictError`),
    which is never retried: read the stream again. To have the SDK do the cut for
    you, use :func:`ssf_stream_edit`.
    """
    return models.SsfStreamInput(
        audience=stream.audience,
        delivery_method=stream.delivery_method,
        description=stream.description,
        endpoint_url=stream.endpoint_url,
        events_allowed=list(stream.events_allowed),
        events_requested=list(stream.events_requested),
        expected_updated_at=stream.updated_at,
        receiver_client_id=stream.receiver_client_id,
        status=stream.status,
        status_reason=stream.status_reason,
        subject_format=stream.subject_format,
    )


def ssf_stream_edit(
    stream: models.SsfStream, changes: Mapping[str, Any] | None = None
) -> models.SsfStreamInput:
    """The **change-taking** read-modify-write form for ``ssf.update_stream``
    (CONTRACT §32.2, contract 1.62): ``(stream, changes) -> body``.

    ``stream`` is what ``ssf.get_stream`` returned and ``changes`` maps
    :class:`~axiam_sdk.management.models.SsfStreamInput` member names to their new
    values. The result is :func:`ssf_stream_input` of the read with the changes
    applied, and it:

    * sends ``events_requested`` **as read** -- ``[]`` stays ``[]``, never omitted,
      because absent would reset a receiver's narrowing to every event of
      ``events_allowed``;
    * sends ``expected_updated_at`` as read -- the response's **own string**, not a
      re-rendered instant -- so an update that another write (the receiver's pause
      or narrowing included) overtook answers ``409``
      (:class:`~axiam_sdk.management.ConflictError`, never retried) rather than
      putting the old value back;
    * **cuts** ``events_requested`` to the new ``events_allowed`` when ``changes``
      lowers the ceiling: the entries of the read ``events_requested`` that are in
      the new ceiling, in their order.

    An ``events_requested`` or an ``expected_updated_at`` named in ``changes`` is
    sent as given (the server judges it; an ``expected_updated_at`` of ``None``
    drops the condition and is never sent as ``null``). ``authorization_header``
    and ``clear_authorization_header`` are as in :func:`ssf_stream_input`: left
    unset, so the stored header is kept unless ``changes`` names one.

    Raises:
        ValidationError: locally, with no request, when ``changes`` names a member
            ``SsfStreamInput`` does not have, or a value it rejects.
    """
    body = ssf_stream_input(stream)
    names = type(body).model_fields
    given = dict(changes or {})
    for name in given:
        if name not in names:
            raise local_refusal("ssf.update_stream", name, "is not a member of SsfStreamInput")
    if "events_allowed" in given and "events_requested" not in given:
        ceiling = set(given["events_allowed"] or ())
        given["events_requested"] = [e for e in stream.events_requested if e in ceiling]
    edited = body.model_dump(exclude_unset=True)
    edited.update(given)
    return models.SsfStreamInput.model_validate(edited)
