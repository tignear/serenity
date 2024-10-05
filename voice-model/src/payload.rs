//! Message bodies used in gateway event-handling.
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use tls_codec::{
    Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait, Size as TlsSizeTrait,
    TlsDeserialize, TlsSerialize, TlsSize, TlsVecU8, VLBytes,
};

use crate::id::*;
use crate::protocol_data::ProtocolData;
use crate::speaking_state::SpeakingState;
use crate::util::json_safe_u64;

/// Message indicating that another user has connected to the voice channel.
///
/// Acts as a source of UserId+SSRC identification.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub struct ClientConnect {
    /// SSRC of any audio packets sent by this newly joined user.
    pub audio_ssrc: u32,
    /// ID of the connecting user.
    pub user_id: UserId,
    /// SSRC of any audio packets sent by this newly joined user.
    ///
    /// Bots should not see any packets with this SSRC.
    pub video_ssrc: u32,
}
/// Message indicating that another user has disconnected from the voice channel.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub struct ClientDisconnect {
    /// Id of the disconnected user.
    pub user_id: UserId,
}
/// Includes the transition ID and protocol version for the transition.
/// The protocol only uses this opcode to indicate when a downgrade to protocol version 0 is upcoming.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub struct DavePrepareTransition {
    /// should be 0
    pub protocol_version: u32,
    pub transition_id: u32,
}
/// Includes the previously announced transition ID to execute.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub struct DaveExecuteTransition {
    pub transition_id: u32,
}

/// Includes the previously announced transition ID that the client is ready to execute.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub struct DaveTransitionReady {
    pub transition_id: u16,
}

/// Includes the epoch ID and protocol version for the upcoming epoch.
/// It is sent from the server to clients to announce upcoming protocol version changes.
/// When the epoch ID is equal to 1, this message indicates that a new MLS group is to be created for the given protocol version.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub struct DavePrepareEpoch {
    pub protocol_version: u32,
    pub epoch: u32,
}

/// Includes the transition ID in which the invalid Commit or Welcome was received.
/// This message asks the voice gateway to remove and re-add a member to an MLS group so the member can recover from receiving an unprocessable Commit or Welcome.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub struct DaveMlsInvalidCommitWelcome {
    pub transition_id: u32,
}

/**
 * Binary Messages
 */
pub type SignaturePublicKey = VLBytes;

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[repr(u16)]
pub enum Credential {
    #[tls_codec(discriminant = 1)]
    Basic(VLBytes) = 1,
}
#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct ExternalSender {
    pub signature_key: SignaturePublicKey,
    pub credential: Credential,
}




#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[repr(u16)]
pub enum ProtocolVersion {
    Mls10 = 1,
}
#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[repr(u16)]
pub enum Ciphersuite {
    Dhkemp256Aes128gcmSha256P256=2,
}
#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct Extension {
    extension_type: u16,
    extension_data: VLBytes,
}
type ExtensionType = u16;

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[repr(u16)]
pub enum ProposalType {
    Add = 0x0001,
    Remove = 0x0003,
}
#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[repr(u16)]
pub enum CredentialType {
    Basic = 1,
}
#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct Capabilities {
    pub versions: Vec<ProtocolVersion>,
    pub cipher_suites: Vec<Ciphersuite>,
    pub extensions: Vec<ExtensionType>,
    pub proposals: Vec<ProposalType>,
    pub credentials: Vec<CredentialType>,
}
#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct LifeTime {
    not_before: u64,
    not_after: u64,
}
#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[repr(u8)]
pub enum LeafNodeSource {
    #[tls_codec(discriminant = 1)]
    KeyPackage(LifeTime),
    #[tls_codec(discriminant = 2)]
    Update = 2,
    #[tls_codec(discriminant = 3)]
    Commit(VLBytes),
}
#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct LeafNode {
    pub encryption_key: VLBytes,
    pub signature_key: VLBytes,
    pub credential: Credential,
    pub capabilities: Capabilities,
    pub leaf_node_source: LeafNodeSource,
    pub extensions: Vec<Extension>,
    pub signature: VLBytes,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct KeyPackage {
    pub version: ProtocolVersion,
    pub cipher_suite: Ciphersuite,
    pub init_key: VLBytes,
    pub leaf_node: LeafNode,
    pub extensions: Vec<Extension>,
    pub signature: VLBytes,
}
#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct DaveMlsKeyPackage {
    pub key_package: KeyPackage,
}

/// Used to keep the websocket connection alive.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Heartbeat {
    /// Random number generated by the client, to be mirrored by the server.
    pub nonce: u64,
}

/// Heartbeat ACK, received by the client to show the server's receipt of a heartbeat.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct HeartbeatAck {
    /// Random 64-bit number previously generated by the client, mirrored by the server.
    #[serde(with = "json_safe_u64")]
    pub nonce: u64,
}

/// Used to determine how often the client must send a heartbeat.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct Hello {
    /// Number of milliseconds to wait between sending heartbeat messages.
    pub heartbeat_interval: f64,
}

/// Used to begin a voice websocket connection.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub struct Identify {
    /// GuildId which the target voice channel belongs to.
    pub server_id: GuildId,
    /// Authentication session received from Discord's main gateway as part of a
    /// `"VOICE_STATE_UPDATE"` message.
    pub session_id: String,
    /// Authentication token received from Discord's main gateway as part of a
    /// `"VOICE_SERVER_UPDATE"` message.
    pub token: String,
    /// UserId of the client who is connecting.
    pub user_id: UserId,
    // The version of DAVE that the client supports. 0 is not supported.
    pub max_dave_protocol_version: u32,
}

/// RTP server's connection offer and supported encryption modes.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub struct Ready {
    /// IP address of the call's allocated RTP server.
    pub ip: IpAddr,
    /// Set of voice encryption modes offered by the server.
    pub modes: Vec<String>,
    /// Destination port on the call's allocated RTP server.
    pub port: u16,
    /// RTP synchronisation source assigned by the server to the client.
    pub ssrc: u32,
}

/// Sent by the client after a disconnect to attempt to resume a session.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub struct Resume {
    /// GuildId which the target voice channel belongs to.
    pub server_id: GuildId,
    /// Authentication session received from Discord's main gateway as part of a
    /// `"VOICE_STATE_UPDATE"` message.
    pub session_id: String,
    /// Authentication token received from Discord's main gateway as part of a
    /// `"VOICE_SERVER_UPDATE"` message.
    pub token: String,
}

/// Used to select the voice protocol and encryption mechanism.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub struct SelectProtocol {
    /// Client's response to encryption/connection negotiation.
    pub data: ProtocolData,
    /// Transport protocol.
    ///
    /// Currently, `"udp"` is the only known accepted value.
    pub protocol: String,
}

/// Server's confirmation of a negotiated encryption scheme.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub struct SessionDescription {
    /// The negotiated encryption mode.
    pub mode: String,
    /// Key used for encryption of RTP payloads using the chosen mode.
    pub secret_key: Vec<u8>,
    /// The version of DAVE. 0 means not to use DAVE.
    pub dave_protocol_version: u32,
}

/// Used to indicate which users are speaking, or to inform Discord that the client is now
/// speaking.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub struct Speaking {
    /// Function currently unknown.
    ///
    /// Docs suggest setting to `Some(0)` when sending this message as a client.
    pub delay: Option<u32>,
    /// How/whether a user has started/stopped speaking.
    pub speaking: SpeakingState,
    /// RTP synchronisation source of the speaker.
    pub ssrc: u32,
    /// User ID of the speaker, included in messages *received from* the server.
    ///
    /// Used alongside the SSRC to map individual packets to their sender.
    pub user_id: Option<UserId>,
}
