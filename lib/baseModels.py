from typing import Optional, List, Dict, Any
from pydantic import BaseModel

class Peer(BaseModel):
    IpAddress: str
    Port: str
    Hostname: str
    Connected: bool
    TransportProtocol: str
    PeerType: str
    LastConnectTimestamp: str
    LastDisconnectTimestamp: str
    ReconnectionCount: int
    Metadata: str

    def update(self, **updatedData):
        for modelField, modelValue in updatedData.items():
            setattr(self, modelField, modelValue)

class InboundData(BaseModel):
    SenderIp: str
    SenderPort: str
    LocalIp: Optional[str] = ""
    LocalPort: Optional[str] = ""
    InitialReceiveTimestamp: int
    InboundHex: str

    def update(self, **updatedData):
        for modelField, modelValue in updatedData.items():
            setattr(self, modelField, modelValue)

class OutboundData(BaseModel):
    DestinationIp: str
    DestinationPort: str
    InitialReceiveTimestamp: int
    OutboundHex: str

    def update(self, **updatedData):
        for modelField, modelValue in updatedData.items():
            setattr(self, modelField, modelValue)

class LocationInfo2G(BaseModel):
    vlr: Optional[str]
    sgsn: Optional[str]
    msc: Optional[str]

class SubscriberInfo(BaseModel):
    location_info_2g: LocationInfo2G
    apns: List[Dict[str, Any]]
    msisdn: str
    imsi: str
