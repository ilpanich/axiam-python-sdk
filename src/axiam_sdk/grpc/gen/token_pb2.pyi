from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ValidateTokenRequest(_message.Message):
    __slots__ = ("access_token",)
    ACCESS_TOKEN_FIELD_NUMBER: _ClassVar[int]
    access_token: str
    def __init__(self, access_token: _Optional[str] = ...) -> None: ...

class ValidateTokenResponse(_message.Message):
    __slots__ = ("valid", "subject_id", "tenant_id", "org_id", "exp", "cnf", "token_type")
    VALID_FIELD_NUMBER: _ClassVar[int]
    SUBJECT_ID_FIELD_NUMBER: _ClassVar[int]
    TENANT_ID_FIELD_NUMBER: _ClassVar[int]
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    EXP_FIELD_NUMBER: _ClassVar[int]
    CNF_FIELD_NUMBER: _ClassVar[int]
    TOKEN_TYPE_FIELD_NUMBER: _ClassVar[int]
    valid: bool
    subject_id: str
    tenant_id: str
    org_id: str
    exp: int
    cnf: CnfClaim
    token_type: str
    def __init__(self, valid: bool = ..., subject_id: _Optional[str] = ..., tenant_id: _Optional[str] = ..., org_id: _Optional[str] = ..., exp: _Optional[int] = ..., cnf: _Optional[_Union[CnfClaim, _Mapping]] = ..., token_type: _Optional[str] = ...) -> None: ...

class CnfClaim(_message.Message):
    __slots__ = ("x5t_s256", "jkt")
    X5T_S256_FIELD_NUMBER: _ClassVar[int]
    JKT_FIELD_NUMBER: _ClassVar[int]
    x5t_s256: str
    jkt: str
    def __init__(self, x5t_s256: _Optional[str] = ..., jkt: _Optional[str] = ...) -> None: ...

class RptPermission(_message.Message):
    __slots__ = ("resource_id", "resource_scopes", "exp")
    RESOURCE_ID_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_SCOPES_FIELD_NUMBER: _ClassVar[int]
    EXP_FIELD_NUMBER: _ClassVar[int]
    resource_id: str
    resource_scopes: _containers.RepeatedScalarFieldContainer[str]
    exp: int
    def __init__(self, resource_id: _Optional[str] = ..., resource_scopes: _Optional[_Iterable[str]] = ..., exp: _Optional[int] = ...) -> None: ...

class IntrospectTokenRequest(_message.Message):
    __slots__ = ("access_token",)
    ACCESS_TOKEN_FIELD_NUMBER: _ClassVar[int]
    access_token: str
    def __init__(self, access_token: _Optional[str] = ...) -> None: ...

class IntrospectTokenResponse(_message.Message):
    __slots__ = ("active", "sub", "tenant_id", "org_id", "iss", "iat", "exp", "jti", "scope", "client_id", "token_type", "cnf", "permissions", "ext_exchange_iss")
    ACTIVE_FIELD_NUMBER: _ClassVar[int]
    SUB_FIELD_NUMBER: _ClassVar[int]
    TENANT_ID_FIELD_NUMBER: _ClassVar[int]
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ISS_FIELD_NUMBER: _ClassVar[int]
    IAT_FIELD_NUMBER: _ClassVar[int]
    EXP_FIELD_NUMBER: _ClassVar[int]
    JTI_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    CLIENT_ID_FIELD_NUMBER: _ClassVar[int]
    TOKEN_TYPE_FIELD_NUMBER: _ClassVar[int]
    CNF_FIELD_NUMBER: _ClassVar[int]
    PERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    EXT_EXCHANGE_ISS_FIELD_NUMBER: _ClassVar[int]
    active: bool
    sub: str
    tenant_id: str
    org_id: str
    iss: str
    iat: int
    exp: int
    jti: str
    scope: str
    client_id: str
    token_type: str
    cnf: CnfClaim
    permissions: _containers.RepeatedCompositeFieldContainer[RptPermission]
    ext_exchange_iss: str
    def __init__(self, active: bool = ..., sub: _Optional[str] = ..., tenant_id: _Optional[str] = ..., org_id: _Optional[str] = ..., iss: _Optional[str] = ..., iat: _Optional[int] = ..., exp: _Optional[int] = ..., jti: _Optional[str] = ..., scope: _Optional[str] = ..., client_id: _Optional[str] = ..., token_type: _Optional[str] = ..., cnf: _Optional[_Union[CnfClaim, _Mapping]] = ..., permissions: _Optional[_Iterable[_Union[RptPermission, _Mapping]]] = ..., ext_exchange_iss: _Optional[str] = ...) -> None: ...
