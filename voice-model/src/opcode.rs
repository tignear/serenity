use serde_repr::{Deserialize_repr, Serialize_repr};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

/// An enum representing the [voice opcodes].
///
/// [voice opcodes]: https://discord.com/developers/docs/topics/opcodes-and-status-codes#voice
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize_repr, Serialize_repr,TlsDeserialize,TlsSerialize,TlsSize
)]
#[non_exhaustive]
#[repr(u8)]
pub enum Opcode {
    /// Used to begin a voice websocket connection.
    Identify = 0,
    /// Used to select the voice protocol.
    SelectProtocol = 1,
    /// Used to complete the websocket handshake.
    Ready = 2,
    /// Used to keep the websocket connection alive.
    Heartbeat = 3,
    /// Server's confirmation of a negotiated encryption scheme.
    SessionDescription = 4,
    /// Used to indicate which users are speaking, or to inform Discord that the client is now speaking.
    Speaking = 5,
    /// Heartbeat ACK, received by the client to show the server's receipt of a heartbeat.
    HeartbeatAck = 6,
    /// Sent after a disconnect to attempt to resume a session.
    Resume = 7,
    /// Used to determine how often the client must send a heartbeat.
    Hello = 8,
    /// Sent by the server if a session could successfully be resumed.
    Resumed = 9,
    /// Message indicating that another user has connected to the voice channel.
    ClientConnect = 12,
    /// Message indicating that another user has disconnected from the voice channel.
    ClientDisconnect = 13,
    /// A downgrade from the DAVE protocol is upcoming.
    DavePrepareTransition = 21,
    /// Execute a previously announced protocol transition.
    DaveExecuteTransition = 22,
    /// Acknowledge readiness previously announced transition.
    DaveTransitionReady = 23,
    /// A DAVE protocol version or group change is upcoming.
    DavePrepareEpoch = 24,
    /// Credential and public key for MLS external sender.
    DaveMlsExternalSender = 25,
    /// MLS Key Package for pending group member.
    DaveMlsKeyPackage = 26,
    /// MLS Proposals to be appended or revoked.
    DaveMlsProposals = 27,
    /// MLS Commit with optional MLS Welcome messages
    DaveMlsCommitWelcome = 28,
    /// MLS Commit to be processed for upcoming transition
    DaveMlsAnnounceCommitTransition = 29,
    /// MLS Welcome to group for upcoming transition.
    DaveMlsWelcome = 30,
    /// Flag invalid commit or welcome, request re-add.
    DaveMlsInvalidCommitWelcome = 31,
}
