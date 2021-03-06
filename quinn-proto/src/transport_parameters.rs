//! QUIC connection transport parameters
//!
//! The `TransportParameters` type is used to represent the transport parameters
//! negotiated by peers while establishing a QUIC connection. This process
//! happens as part of the establishment of the TLS session. As such, the types
//! contained in this modules should generally only be referred to by custom
//! implementations of the `crypto::Session` trait.

use std::{
    convert::TryInto,
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
};

use bytes::{buf::ext::BufExt as _, Buf, BufMut};
use err_derive::Error;

use crate::{
    cid_queue::CidQueue,
    coding::{BufExt, BufMutExt, UnexpectedEnd},
    config::{EndpointConfig, ServerConfig, TransportConfig},
    crypto,
    shared::{ConnectionId, ResetToken},
    Side, TransportError, VarInt, MAX_CID_SIZE, RESET_TOKEN_SIZE,
};

// Apply a given macro to a list of all the transport parameters having integer types, along with
// their codes and default values. Using this helps us avoid error-prone duplication of the
// contained information across decoding, encoding, and the `Default` impl. Whenever we want to do
// something with transport parameters, we'll handle the bulk of cases by writing a macro that
// takes a list of arguments in this form, then passing it to this macro.
macro_rules! apply_params {
    ($macro:ident) => {
        $macro! {
            // #[doc] name (id) = default,
            /// Milliseconds, disabled if zero
            max_idle_timeout(0x0001) = 0,
            /// Limits the size of UDP payloads that the endpoint is willing to receive
            max_udp_payload_size(0x0003) = 65527,

            /// Initial value for the maximum amount of data that can be sent on the connection
            initial_max_data(0x0004) = 0,
            /// Initial flow control limit for locally-initiated bidirectional streams
            initial_max_stream_data_bidi_local(0x0005) = 0,
            /// Initial flow control limit for peer-initiated bidirectional streams
            initial_max_stream_data_bidi_remote(0x0006) = 0,
            /// Initial flow control limit for unidirectional streams
            initial_max_stream_data_uni(0x0007) = 0,

            /// Initial maximum number of bidirectional streams the peer may initiate
            initial_max_streams_bidi(0x0008) = 0,
            /// Initial maximum number of unidirectional streams the peer may initiate
            initial_max_streams_uni(0x0009) = 0,

            /// Exponent used to decode the ACK Delay field in the ACK frame
            ack_delay_exponent(0x000a) = 3,
            /// Maximum amount of time in milliseconds by which the endpoint will delay sending
            /// acknowledgments
            max_ack_delay(0x000b) = 25,
            /// Maximum number of connection IDs from the peer that an endpoint is willing to store
            active_connection_id_limit(0x000e) = 2,
        }
    };
}

macro_rules! make_struct {
    {$($(#[$doc:meta])* $name:ident ($code:expr) = $default:expr,)*} => {
        /// Transport parameters used to negotiate connection-level preferences between peers
        #[derive(Debug, Copy, Clone, Eq, PartialEq)]
        pub struct TransportParameters {
            $($(#[$doc])* pub(crate) $name : u64,)*

            /// Does the endpoint support active connection migration
            pub(crate) disable_active_migration: bool,
            /// Maximum size for datagram frames
            pub(crate) max_datagram_frame_size: Option<VarInt>,

            // Server-only
            /// The DCID from the first Initial packet; must be included if a Retry packet was sent
            pub(crate) original_connection_id: Option<ConnectionId>,
            /// Token used by the client to verify a stateless reset from the server
            pub(crate) stateless_reset_token: Option<ResetToken>,
            /// The server's preferred address for communication after handshake completion
            pub(crate) preferred_address: Option<PreferredAddress>,
        }

        impl Default for TransportParameters {
            /// Standard defaults, used if the peer does not supply a given parameter.
            fn default() -> Self {
                Self {
                    $($name: $default,)*

                    disable_active_migration: false,
                    max_datagram_frame_size: None,

                    original_connection_id: None,
                    stateless_reset_token: None,
                    preferred_address: None,
                }
            }
        }
    }
}

apply_params!(make_struct);

impl TransportParameters {
    pub(crate) fn new<S>(
        config: &TransportConfig,
        endpoint_config: &EndpointConfig<S>,
        server_config: Option<&ServerConfig<S>>,
    ) -> Self
    where
        S: crypto::Session,
    {
        TransportParameters {
            initial_max_streams_bidi: config.stream_window_bidi,
            initial_max_streams_uni: config.stream_window_uni,
            initial_max_data: config.receive_window,
            initial_max_stream_data_bidi_local: config.stream_receive_window,
            initial_max_stream_data_bidi_remote: config.stream_receive_window,
            initial_max_stream_data_uni: config.stream_receive_window,
            max_udp_payload_size: endpoint_config.max_udp_payload_size,
            max_idle_timeout: config.max_idle_timeout.map_or(0, |x| {
                x.as_millis()
                    .try_into()
                    .expect("setter guarantees this is in-bounds")
            }),
            max_ack_delay: 0,
            disable_active_migration: server_config.map_or(false, |c| !c.migration),
            active_connection_id_limit: if endpoint_config.local_cid_len == 0 {
                2 // i.e. default, i.e. unsent
            } else {
                // + 1 to account for the currently used CID, which isn't kept in the queue
                CidQueue::LEN as u64 + 1
            },
            max_datagram_frame_size: config
                .datagram_receive_buffer_size
                .map(|x| (x.min(u16::max_value().into()) as u16).into()),
            ..Self::default()
        }
    }

    /// Check that these parameters are legal when resuming from
    /// certain cached parameters
    pub(crate) fn validate_0rtt(&self, cached: &TransportParameters) -> Result<(), TransportError> {
        if cached.initial_max_data < self.initial_max_data
            || cached.initial_max_stream_data_bidi_local < self.initial_max_stream_data_bidi_local
            || cached.initial_max_stream_data_bidi_remote < self.initial_max_stream_data_bidi_remote
            || cached.initial_max_stream_data_uni < self.initial_max_stream_data_uni
            || cached.initial_max_streams_bidi < self.initial_max_streams_bidi
            || cached.initial_max_streams_uni < self.initial_max_streams_uni
            || cached.max_datagram_frame_size < self.max_datagram_frame_size
        {
            return Err(TransportError::PROTOCOL_VIOLATION(
                "0-RTT accepted with incompatible transport parameters",
            ));
        }
        Ok(())
    }
}

/// A server's preferred address
///
/// This is communicated as a transport parameter during TLS session establishment.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct PreferredAddress {
    address_v4: Option<SocketAddrV4>,
    address_v6: Option<SocketAddrV6>,
    connection_id: ConnectionId,
    stateless_reset_token: [u8; RESET_TOKEN_SIZE],
}

impl PreferredAddress {
    fn wire_size(&self) -> u16 {
        4 + 2 + 16 + 2 + 1 + self.connection_id.len() as u16 + 16
    }

    fn write<W: BufMut>(&self, w: &mut W) {
        w.write(self.address_v4.map_or(Ipv4Addr::UNSPECIFIED, |x| *x.ip()));
        w.write::<u16>(self.address_v4.map_or(0, |x| x.port()));
        w.write(self.address_v6.map_or(Ipv6Addr::UNSPECIFIED, |x| *x.ip()));
        w.write::<u16>(self.address_v6.map_or(0, |x| x.port()));
        w.write::<u8>(self.connection_id.len() as u8);
        w.put_slice(&self.connection_id);
        w.put_slice(&self.stateless_reset_token);
    }

    fn read<R: Buf>(r: &mut R) -> Result<Self, Error> {
        let ip_v4 = r.get::<Ipv4Addr>()?;
        let port_v4 = r.get::<u16>()?;
        let ip_v6 = r.get::<Ipv6Addr>()?;
        let port_v6 = r.get::<u16>()?;
        let cid_len = r.get::<u8>()?;
        if r.remaining() < cid_len as usize || cid_len > MAX_CID_SIZE as u8 {
            return Err(Error::Malformed);
        }
        let mut stage = [0; MAX_CID_SIZE];
        r.copy_to_slice(&mut stage[0..cid_len as usize]);
        let cid = ConnectionId::new(&stage[0..cid_len as usize]);
        if r.remaining() < 16 {
            return Err(Error::Malformed);
        }
        let mut token = [0; RESET_TOKEN_SIZE];
        r.copy_to_slice(&mut token);
        let address_v4 = if ip_v4.is_unspecified() && port_v4 == 0 {
            None
        } else {
            Some(SocketAddrV4::new(ip_v4, port_v4))
        };
        let address_v6 = if ip_v6.is_unspecified() && port_v6 == 0 {
            None
        } else {
            Some(SocketAddrV6::new(ip_v6, port_v6, 0, 0))
        };
        if address_v4.is_none() && address_v6.is_none() {
            return Err(Error::IllegalValue);
        }
        Ok(Self {
            address_v4,
            address_v6,
            connection_id: cid,
            stateless_reset_token: token,
        })
    }
}

/// Errors encountered while decoding `TransportParameters`
#[derive(Debug, Copy, Clone, Eq, PartialEq, Error)]
pub enum Error {
    /// Parameters that are semantically invalid
    #[error(display = "parameter had illegal value")]
    IllegalValue,
    /// Catch-all error for problems while decoding transport parameters
    #[error(display = "parameters were malformed")]
    Malformed,
}

impl From<Error> for TransportError {
    fn from(e: Error) -> Self {
        match e {
            Error::IllegalValue => TransportError::TRANSPORT_PARAMETER_ERROR("illegal value"),
            Error::Malformed => TransportError::TRANSPORT_PARAMETER_ERROR("malformed"),
        }
    }
}

impl From<UnexpectedEnd> for Error {
    fn from(_: UnexpectedEnd) -> Self {
        Error::Malformed
    }
}

impl TransportParameters {
    /// Encode `TransportParameters` into buffer
    pub fn write<W: BufMut>(&self, w: &mut W) {
        macro_rules! write_params {
            {$($(#[$doc:meta])* $name:ident ($code:expr) = $default:expr,)*} => {
                $(
                    if self.$name != $default {
                        w.write_var($code);
                        w.write_var(VarInt::from_u64(self.$name).expect("value too large").size() as u64);
                        w.write_var(self.$name);
                    }
                )*
            }
        }
        apply_params!(write_params);

        // Add a reserved parameter to keep people on their toes
        w.write_var(31 * 5 + 27);
        w.write_var(0);

        if let Some(ref x) = self.original_connection_id {
            w.write_var(0x00);
            w.write_var(x.len() as u64);
            w.put_slice(x);
        }

        if let Some(ref x) = self.stateless_reset_token {
            w.write_var(0x02);
            w.write_var(16);
            w.put_slice(x);
        }

        if self.disable_active_migration {
            w.write_var(0x0c);
            w.write_var(0);
        }

        if let Some(x) = self.max_datagram_frame_size {
            w.write_var(0x20);
            w.write_var(x.size() as u64);
            w.write(x);
        }

        if let Some(ref x) = self.preferred_address {
            w.write_var(0x000d);
            w.write_var(x.wire_size() as u64);
            x.write(w);
        }
    }

    /// Decode `TransportParameters` from buffer
    pub fn read<R: Buf>(side: Side, r: &mut R) -> Result<Self, Error> {
        // Initialize to protocol-specified defaults
        let mut params = TransportParameters::default();

        // State to check for duplicate transport parameters.
        macro_rules! param_state {
            {$($(#[$doc:meta])* $name:ident ($code:expr) = $default:expr,)*} => {{
                struct ParamState {
                    $($name: bool,)*
                }

                ParamState {
                    $($name: false,)*
                }
            }}
        }
        let mut got = apply_params!(param_state);

        while r.has_remaining() {
            let id = r.get_var()?;
            let len = r.get_var()?;
            if (r.remaining() as u64) < len {
                return Err(Error::Malformed);
            }

            match id {
                0x00 => {
                    if len > MAX_CID_SIZE as u64 || params.original_connection_id.is_some() {
                        return Err(Error::Malformed);
                    }
                    let mut staging = [0; MAX_CID_SIZE];
                    r.copy_to_slice(&mut staging[0..len as usize]);
                    params.original_connection_id =
                        Some(ConnectionId::new(&staging[0..len as usize]));
                }
                0x02 => {
                    if len != 16 || params.stateless_reset_token.is_some() {
                        return Err(Error::Malformed);
                    }
                    let mut tok = [0; RESET_TOKEN_SIZE];
                    r.copy_to_slice(&mut tok);
                    params.stateless_reset_token = Some(tok.into());
                }
                0x0c => {
                    if len != 0 || params.disable_active_migration {
                        return Err(Error::Malformed);
                    }
                    params.disable_active_migration = true;
                }
                0x0d => {
                    if params.preferred_address.is_some() {
                        return Err(Error::Malformed);
                    }
                    params.preferred_address =
                        Some(PreferredAddress::read(&mut r.take(len as usize))?);
                }
                0x20 => {
                    if len > 8 || params.max_datagram_frame_size.is_some() {
                        return Err(Error::Malformed);
                    }
                    params.max_datagram_frame_size = Some(r.get().unwrap());
                }
                _ => {
                    macro_rules! parse {
                        {$($(#[$doc:meta])* $name:ident ($code:expr) = $default:expr,)*} => {
                            match id {
                                $($code => {
                                    params.$name = r.get_var()?;
                                    if len != VarInt::from_u64(params.$name).unwrap().size() as u64 || got.$name { return Err(Error::Malformed); }
                                    got.$name = true;
                                })*
                                _ => r.advance(len as usize),
                            }
                        }
                    }
                    apply_params!(parse);
                }
            }
        }

        // Semantic validation
        if params.ack_delay_exponent > 20
            || params.max_ack_delay >= 1 << 14
            || params.active_connection_id_limit < 2
            || params.max_udp_payload_size < 1200
            || (side.is_server()
                && (params.original_connection_id.is_some()
                    || params.stateless_reset_token.is_some()
                    || params.preferred_address.is_some()))
        {
            return Err(Error::IllegalValue);
        }

        Ok(params)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn coding() {
        let mut buf = Vec::new();
        let params = TransportParameters {
            initial_max_streams_bidi: 16,
            initial_max_streams_uni: 16,
            ack_delay_exponent: 2,
            max_udp_payload_size: 1200,
            preferred_address: Some(PreferredAddress {
                address_v4: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 42)),
                address_v6: None,
                connection_id: ConnectionId::new(&[]),
                stateless_reset_token: [0xab; RESET_TOKEN_SIZE],
            }),
            ..TransportParameters::default()
        };
        params.write(&mut buf);
        assert_eq!(
            TransportParameters::read(Side::Client, &mut buf.as_slice()).unwrap(),
            params
        );
    }
}
