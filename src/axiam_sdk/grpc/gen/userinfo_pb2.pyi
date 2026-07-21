from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class GetUserInfoRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GetUserInfoResponse(_message.Message):
    __slots__ = ("sub", "tenant_id", "org_id", "email", "preferred_username")
    SUB_FIELD_NUMBER: _ClassVar[int]
    TENANT_ID_FIELD_NUMBER: _ClassVar[int]
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    PREFERRED_USERNAME_FIELD_NUMBER: _ClassVar[int]
    sub: str
    tenant_id: str
    org_id: str
    email: str
    preferred_username: str
    def __init__(self, sub: _Optional[str] = ..., tenant_id: _Optional[str] = ..., org_id: _Optional[str] = ..., email: _Optional[str] = ..., preferred_username: _Optional[str] = ...) -> None: ...
