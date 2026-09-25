from typing import Any, Dict, Optional

from pydantic import BaseModel


class UserInfo(BaseModel):
    name: Optional[str] = None
    target_name: Optional[str] = None
    target_sid: Optional[str] = None
    target_domain: Optional[str] = None
    subject_name: Optional[str] = None
    subject_sid: Optional[str] = None
    subject_domain: Optional[str] = None


class HostInfo(BaseModel):
    name: Optional[str] = None
    workstation: Optional[str] = None


class AuthenticationInfo(BaseModel):
    logon_type: Optional[int] = None
    logon_type_name: Optional[str] = None
    logon_process: Optional[str] = None
    package: Optional[str] = None


class NetworkInfo(BaseModel):
    source_ip: Optional[str] = None
    source_port: Optional[int] = None


class ProcessInfo(BaseModel):
    name: Optional[str] = None
    pid: Optional[str] = None


class CorrelationInfo(BaseModel):
    logon_id: Optional[str] = None
    linked_logon_id: Optional[str] = None


class SentraEvent(BaseModel):
    id: str
    timestamp: Optional[str] = None

    source: str
    event_type: str
    event_name: str
    event_id: int

    user: UserInfo
    host: HostInfo
    authentication: AuthenticationInfo
    network: NetworkInfo
    process: ProcessInfo
    correlation: CorrelationInfo

    raw: Dict[str, Any] = {}