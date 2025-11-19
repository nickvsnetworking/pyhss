from typing import Optional, List, Dict
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

class SubscriberInfo(BaseModel):
    apns: List[Dict[str, str]]
    msisdn: str
    imsi: str
