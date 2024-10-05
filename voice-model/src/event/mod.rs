mod from;
#[cfg(test)]
mod tests;

use std::convert::TryFrom;

use serde::de::value::U8Deserializer;
use serde::de::{Deserializer, Error as DeError, IntoDeserializer, MapAccess, Unexpected, Visitor};
use serde::ser::{SerializeStruct, Serializer};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use tls_codec::{
    Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait, Size as TlsSizeTrait,
    TlsDeserialize, TlsSerialize, TlsSize, TlsVecU8, VLBytes,
};

use crate::opcode::Opcode;
use crate::payload::*;

/// A representation of data received for voice gateway events.
#[derive(Clone, Debug)]
#[repr(u8)]
#[non_exhaustive]
pub enum Event {
    /// Used to begin a voice websocket connection.
    Identify(Identify) = 0,
    /// Used to select the voice protocol and encryption mechanism.
    SelectProtocol(SelectProtocol) = 1,
    /// Server's response to the client's Identify operation. Contains session-specific
    /// information, e.g. SSRC, and supported encryption modes.
    Ready(Ready) = 2,
    /// Periodic messages used to keep the websocket connection alive.
    Heartbeat(Heartbeat) = 3,
    /// Server's confirmation of a negotiated encryption scheme.
    SessionDescription(SessionDescription) = 4,
    /// A voice event denoting that someone is speaking.
    Speaking(Speaking) = 5,
    /// Acknowledgement from the server for a prior voice heartbeat.
    HeartbeatAck(HeartbeatAck) = 6,
    /// Sent by the client after a disconnect to attempt to resume a session.
    Resume(Resume) = 7,
    /// Used to determine how often the client must send a heartbeat.
    Hello(Hello) = 8,
    /// Message received if a Resume request was successful.
    Resumed = 9,
    /// Status update in the current channel, indicating that a user has connected.
    ClientConnect(ClientConnect) = 12,
    /// Status update in the current channel, indicating that a user has disconnected.
    ClientDisconnect(ClientDisconnect) = 13,
    DavePrepareTransition(DavePrepareTransition) = 21,
    DaveExecuteTransition(DaveExecuteTransition) = 22,
    DaveTransitionReady(DaveTransitionReady) = 23,
    DavePrepareEpoch(DavePrepareEpoch) = 24,
    DaveMlsExternalSenderPackage(Vec<u8>) = 25,
    DaveMlsKeyPackage(Vec<u8>) = 26,
    DaveMlsProposals(Vec<u8>) = 27,
    DaveMlsCommitWelcome(Vec<u8>) = 28,
    DaveMlsAnnounceCommitTransition(Vec<u8>) = 29,
    DaveMlsWelcome(Vec<u8>) = 30,
    DaveMlsInvalidCommitWelcome(DaveMlsInvalidCommitWelcome) = 31,
}
/// A representation of data received for voice gateway events.
#[derive(Clone, Debug)]
#[repr(u8)]
#[non_exhaustive]
pub enum JsonEvent {
    /// Used to begin a voice websocket connection.
    Identify(Identify) = 0,
    /// Used to select the voice protocol and encryption mechanism.
    SelectProtocol(SelectProtocol) = 1,
    /// Server's response to the client's Identify operation. Contains session-specific
    /// information, e.g. SSRC, and supported encryption modes.
    Ready(Ready) = 2,
    /// Periodic messages used to keep the websocket connection alive.
    Heartbeat(Heartbeat) = 3,
    /// Server's confirmation of a negotiated encryption scheme.
    SessionDescription(SessionDescription) = 4,
    /// A voice event denoting that someone is speaking.
    Speaking(Speaking) = 5,
    /// Acknowledgement from the server for a prior voice heartbeat.
    HeartbeatAck(HeartbeatAck) = 6,
    /// Sent by the client after a disconnect to attempt to resume a session.
    Resume(Resume) = 7,
    /// Used to determine how often the client must send a heartbeat.
    Hello(Hello) = 8,
    /// Message received if a Resume request was successful.
    Resumed = 9,
    /// Status update in the current channel, indicating that a user has connected.
    ClientConnect(ClientConnect) = 12,
    /// Status update in the current channel, indicating that a user has disconnected.
    ClientDisconnect(ClientDisconnect) = 13,
    DavePrepareTransition(DavePrepareTransition) = 21,
    DaveExecuteTransition(DaveExecuteTransition) = 22,
    DaveTransitionReady(DaveTransitionReady) = 23,
    DavePrepareEpoch(DavePrepareEpoch) = 24,
    DaveMlsInvalidCommitWelcome(DaveMlsInvalidCommitWelcome) = 31,
}
#[derive(Debug, Clone)]
pub struct BinaryEvent {
    //pub seq: u16,
    pub opcode: Opcode,
    pub data: Vec<u8>,
}
impl TryFrom<BinaryEvent> for Event {
    type Error = ();
    fn try_from(value: BinaryEvent) -> Result<Event, Self::Error> {
        let e = value.data;
        Ok(match value.opcode {
            Opcode::DaveMlsExternalSender => Event::DaveMlsExternalSenderPackage(e),
            Opcode::DaveMlsKeyPackage => Event::DaveMlsKeyPackage(e),
            Opcode::DaveMlsProposals => Event::DaveMlsProposals(e),
            Opcode::DaveMlsCommitWelcome => Event::DaveMlsCommitWelcome(e),
            Opcode::DaveMlsAnnounceCommitTransition => Event::DaveMlsAnnounceCommitTransition(e),
            Opcode::DaveMlsWelcome => Event::DaveMlsWelcome(e),
            _ => Err(())?,
        })
    }
}
impl TlsSizeTrait for BinaryEvent {
    fn tls_serialized_len(&self) -> usize {
        self.data.len() + 1
    }
}
impl TlsSerializeTrait for BinaryEvent {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        writer.write(&[self.opcode as u8])?;
        writer.write(&self.data)?;
        return Ok(self.data.len() + 1);
    }
}
impl TlsDeserializeTrait for BinaryEvent {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        //let seq = u16::tls_deserialize(bytes)?;
        let opcode = Opcode::tls_deserialize(bytes)?;
        let mut data = vec![];
        bytes.read_to_end(&mut data)?;
        Ok(Self { /*seq,*/ opcode, data })
    }
}
impl From<JsonEvent> for Event {
    fn from(value: JsonEvent) -> Self {
        match value {
            JsonEvent::Identify(identify) => Event::Identify(identify),
            JsonEvent::SelectProtocol(select_protocol) => Event::SelectProtocol(select_protocol),
            JsonEvent::Ready(ready) => Event::Ready(ready),
            JsonEvent::Heartbeat(heartbeat) => Event::Heartbeat(heartbeat),
            JsonEvent::SessionDescription(session_description) => {
                Event::SessionDescription(session_description)
            },
            JsonEvent::Speaking(speaking) => Event::Speaking(speaking),
            JsonEvent::HeartbeatAck(heartbeat_ack) => Event::HeartbeatAck(heartbeat_ack),
            JsonEvent::Resume(resume) => Event::Resume(resume),
            JsonEvent::Hello(hello) => Event::Hello(hello),
            JsonEvent::Resumed => Event::Resumed,
            JsonEvent::ClientConnect(client_connect) => Event::ClientConnect(client_connect),
            JsonEvent::ClientDisconnect(client_disconnect) => {
                Event::ClientDisconnect(client_disconnect)
            },
            JsonEvent::DavePrepareTransition(dave_prepare_transition) => {
                Event::DavePrepareTransition(dave_prepare_transition)
            },
            JsonEvent::DaveExecuteTransition(dave_execute_transition) => {
                Event::DaveExecuteTransition(dave_execute_transition)
            },
            JsonEvent::DaveTransitionReady(dave_transition_ready) => {
                Event::DaveTransitionReady(dave_transition_ready)
            },
            JsonEvent::DavePrepareEpoch(dave_prepare_epoch) => {
                Event::DavePrepareEpoch(dave_prepare_epoch)
            },
            JsonEvent::DaveMlsInvalidCommitWelcome(dave_mls_invalid_commit_welcome) => {
                Event::DaveMlsInvalidCommitWelcome(dave_mls_invalid_commit_welcome)
            },
        }
    }
}
impl Event {
    pub fn kind(&self) -> Opcode {
        use Event::*;
        match self {
            Identify(_) => Opcode::Identify,
            SelectProtocol(_) => Opcode::SelectProtocol,
            Ready(_) => Opcode::Ready,
            Heartbeat(_) => Opcode::Heartbeat,
            SessionDescription(_) => Opcode::SessionDescription,
            Speaking(_) => Opcode::Speaking,
            HeartbeatAck(_) => Opcode::HeartbeatAck,
            Resume(_) => Opcode::Resume,
            Hello(_) => Opcode::Hello,
            Resumed => Opcode::Resumed,
            ClientConnect(_) => Opcode::ClientConnect,
            ClientDisconnect(_) => Opcode::ClientDisconnect,
            DavePrepareTransition(_) => Opcode::DavePrepareTransition,
            DaveExecuteTransition(_) => Opcode::DaveExecuteTransition,
            DaveTransitionReady(_) => Opcode::DaveTransitionReady,
            DavePrepareEpoch(_) => Opcode::DavePrepareEpoch,
            DaveMlsInvalidCommitWelcome(_) => Opcode::DaveMlsInvalidCommitWelcome,
            DaveMlsExternalSenderPackage(_) => Opcode::DaveMlsExternalSender,
            DaveMlsKeyPackage(_) => Opcode::DaveMlsKeyPackage,
            DaveMlsProposals(_) => Opcode::DaveMlsProposals,
            DaveMlsCommitWelcome(_) => Opcode::DaveMlsCommitWelcome,
            DaveMlsAnnounceCommitTransition(_) => Opcode::DaveMlsAnnounceCommitTransition,
            DaveMlsWelcome(_) => Opcode::DaveMlsWelcome,
        }
    }
}
impl JsonEvent {
    pub fn kind(&self) -> Opcode {
        use JsonEvent::*;
        match self {
            Identify(_) => Opcode::Identify,
            SelectProtocol(_) => Opcode::SelectProtocol,
            Ready(_) => Opcode::Ready,
            Heartbeat(_) => Opcode::Heartbeat,
            SessionDescription(_) => Opcode::SessionDescription,
            Speaking(_) => Opcode::Speaking,
            HeartbeatAck(_) => Opcode::HeartbeatAck,
            Resume(_) => Opcode::Resume,
            Hello(_) => Opcode::Hello,
            Resumed => Opcode::Resumed,
            ClientConnect(_) => Opcode::ClientConnect,
            ClientDisconnect(_) => Opcode::ClientDisconnect,
            DavePrepareTransition(_) => Opcode::DavePrepareTransition,
            DaveExecuteTransition(_) => Opcode::DaveExecuteTransition,
            DaveTransitionReady(_) => Opcode::DaveTransitionReady,
            DavePrepareEpoch(_) => Opcode::DavePrepareEpoch,
            DaveMlsInvalidCommitWelcome(_) => Opcode::DaveMlsInvalidCommitWelcome,
        }
    }
}
impl Serialize for JsonEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("Event", 2)?;

        s.serialize_field("op", &self.kind())?;

        use JsonEvent::*;
        match self {
            Identify(e) => s.serialize_field("d", e)?,
            SelectProtocol(e) => s.serialize_field("d", e)?,
            Ready(e) => s.serialize_field("d", e)?,
            Heartbeat(e) => s.serialize_field("d", e)?,
            SessionDescription(e) => s.serialize_field("d", e)?,
            Speaking(e) => s.serialize_field("d", e)?,
            HeartbeatAck(e) => s.serialize_field("d", e)?,
            Resume(e) => s.serialize_field("d", e)?,
            Hello(e) => s.serialize_field("d", e)?,
            Resumed => s.serialize_field("d", &None::<()>)?,
            ClientConnect(e) => s.serialize_field("d", e)?,
            ClientDisconnect(e) => s.serialize_field("d", e)?,
            DavePrepareTransition(e) => s.serialize_field("d", e)?,
            DaveExecuteTransition(e) => s.serialize_field("d", e)?,
            DaveTransitionReady(e) => s.serialize_field("d", e)?,
            DavePrepareEpoch(e) => s.serialize_field("d", e)?,
            DaveMlsInvalidCommitWelcome(e) => s.serialize_field("d", e)?,
        }

        s.end()
    }
}

struct EventVisitor;

impl<'de> Visitor<'de> for EventVisitor {
    type Value = Event;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a map with at least two keys ('d', 'op')")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut d = None;
        let mut op = None;

        loop {
            match map.next_key::<&str>()? {
                Some("op") => {
                    let raw = map.next_value::<u8>()?;
                    let des: U8Deserializer<A::Error> = raw.into_deserializer();
                    let valid_op = Opcode::deserialize(des).map_err(|_| {
                        DeError::invalid_value(
                            Unexpected::Unsigned(raw.into()),
                            &"opcode in [0--9] + [12--13]",
                        )
                    })?;
                    op = Some(valid_op);
                },
                // Idea: Op comes first, but missing it is not failure.
                // So, if order correct then we don't need to pass the RawValue back out.
                Some("d") => match op {
                    Some(Opcode::Identify) => return Ok(map.next_value::<Identify>()?.into()),
                    Some(Opcode::SelectProtocol) => {
                        return Ok(map.next_value::<SelectProtocol>()?.into())
                    },
                    Some(Opcode::Ready) => return Ok(map.next_value::<Ready>()?.into()),
                    Some(Opcode::Heartbeat) => return Ok(map.next_value::<Heartbeat>()?.into()),
                    Some(Opcode::HeartbeatAck) => {
                        return Ok(map.next_value::<HeartbeatAck>()?.into())
                    },
                    Some(Opcode::SessionDescription) => {
                        return Ok(map.next_value::<SessionDescription>()?.into())
                    },
                    Some(Opcode::Speaking) => return Ok(map.next_value::<Speaking>()?.into()),
                    Some(Opcode::Resume) => return Ok(map.next_value::<Resume>()?.into()),
                    Some(Opcode::Hello) => return Ok(map.next_value::<Hello>()?.into()),
                    Some(Opcode::Resumed) => {
                        let _ = map.next_value::<Option<()>>()?;
                        return Ok(Event::Resumed);
                    },
                    Some(Opcode::ClientConnect) => {
                        return Ok(map.next_value::<ClientConnect>()?.into())
                    },
                    Some(Opcode::ClientDisconnect) => {
                        return Ok(map.next_value::<ClientDisconnect>()?.into())
                    },
                    Some(Opcode::DaveExecuteTransition) => {
                        return Ok(map.next_value::<DaveExecuteTransition>()?.into())
                    },
                    Some(Opcode::DaveMlsInvalidCommitWelcome) => {
                        return Ok(map.next_value::<DaveMlsInvalidCommitWelcome>()?.into())
                    },
                    Some(Opcode::DavePrepareEpoch) => {
                        return Ok(map.next_value::<DavePrepareEpoch>()?.into())
                    },
                    Some(Opcode::DavePrepareTransition) => {
                        return Ok(map.next_value::<DavePrepareTransition>()?.into())
                    },
                    Some(Opcode::DaveTransitionReady) => {
                        return Ok(map.next_value::<DaveTransitionReady>()?.into())
                    },
                    Some(
                        op @ (Opcode::DaveMlsExternalSender
                        | Opcode::DaveMlsKeyPackage
                        | Opcode::DaveMlsProposals
                        | Opcode::DaveMlsCommitWelcome
                        | Opcode::DaveMlsAnnounceCommitTransition
                        | Opcode::DaveMlsWelcome),
                    ) => {
                        return Err(DeError::invalid_value(
                            Unexpected::Unsigned(op as u64),
                            &"json opcode",
                        ))
                    },
                    None => {
                        d = Some(map.next_value::<&RawValue>()?);
                    },
                },
                Some(_) => {},
                None => {
                    if d.is_none() {
                        return Err(DeError::missing_field("d"));
                    } else if op.is_none() {
                        return Err(DeError::missing_field("op"));
                    }
                },
            }

            if d.is_some() && op.is_some() {
                break;
            }
        }

        let d = d.expect("Struct body known to exist if loop has been escaped.").get();
        let op = op.expect("Struct variant known to exist if loop has been escaped.");

        (match op {
            Opcode::Identify => serde_json::from_str::<Identify>(d).map(Into::into),
            Opcode::SelectProtocol => serde_json::from_str::<SelectProtocol>(d).map(Into::into),
            Opcode::Ready => serde_json::from_str::<Ready>(d).map(Into::into),
            Opcode::Heartbeat => serde_json::from_str::<Heartbeat>(d).map(Into::into),
            Opcode::HeartbeatAck => serde_json::from_str::<HeartbeatAck>(d).map(Into::into),
            Opcode::SessionDescription => {
                serde_json::from_str::<SessionDescription>(d).map(Into::into)
            },
            Opcode::Speaking => serde_json::from_str::<Speaking>(d).map(Into::into),
            Opcode::Resume => serde_json::from_str::<Resume>(d).map(Into::into),
            Opcode::Hello => serde_json::from_str::<Hello>(d).map(Into::into),
            Opcode::Resumed => Ok(Event::Resumed),
            Opcode::ClientConnect => serde_json::from_str::<ClientConnect>(d).map(Into::into),
            Opcode::ClientDisconnect => serde_json::from_str::<ClientDisconnect>(d).map(Into::into),
            Opcode::DavePrepareTransition => {
                serde_json::from_str::<DavePrepareTransition>(d).map(Into::into)
            },
            Opcode::DaveExecuteTransition => {
                serde_json::from_str::<DaveExecuteTransition>(d).map(Into::into)
            },
            Opcode::DaveMlsInvalidCommitWelcome => {
                serde_json::from_str::<DaveMlsInvalidCommitWelcome>(d).map(Into::into)
            },
            Opcode::DavePrepareEpoch => serde_json::from_str::<DavePrepareEpoch>(d).map(Into::into),
            Opcode::DaveTransitionReady => {
                serde_json::from_str::<DaveTransitionReady>(d).map(Into::into)
            },
            Opcode::DaveMlsAnnounceCommitTransition
            | Opcode::DaveMlsExternalSender
            | Opcode::DaveMlsKeyPackage
            | Opcode::DaveMlsProposals
            | Opcode::DaveMlsCommitWelcome
            | Opcode::DaveMlsWelcome => {
                return Err(DeError::invalid_value(Unexpected::Unsigned(op as u64), &"json opcode"))
            },
        })
        .map_err(DeError::custom)
    }
}

impl<'de> Deserialize<'de> for Event {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(EventVisitor)
    }
}
