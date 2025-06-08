use bytes::{BufMut, BytesMut};

use crate::v5::Address;

/// # Response
///
/// ```text
///  +-----+-------+------+----------+----------+
///  | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
///  +-----+-------+------+----------+----------+
///  |  1  | X'00' |  1   | Variable |    2     |
///  +-----+-------+------+----------+----------+
/// ```
///
#[derive(Debug, Clone)]
pub enum Response<'a> {
    Success(&'a Address),
    GeneralFailure,
    ConnectionNotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TTLExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
    Unassigned(u8),
}

#[rustfmt::skip]
impl Response<'_> {
    const SOCKS5_REPLY_SUCCEEDED:                  u8 = 0x00;
    const SOCKS5_REPLY_GENERAL_FAILURE:            u8 = 0x01;
    const SOCKS5_REPLY_CONNECTION_NOT_ALLOWED:     u8 = 0x02;
    const SOCKS5_REPLY_NETWORK_UNREACHABLE:        u8 = 0x03;
    const SOCKS5_REPLY_HOST_UNREACHABLE:           u8 = 0x04;
    const SOCKS5_REPLY_CONNECTION_REFUSED:         u8 = 0x05;
    const SOCKS5_REPLY_TTL_EXPIRED:                u8 = 0x06;
    const SOCKS5_REPLY_COMMAND_NOT_SUPPORTED:      u8 = 0x07;
    const SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

impl Response<'_> {
    #[inline]
    pub fn to_bytes(&self) -> BytesMut {
        let mut bytes = BytesMut::new();

        let (reply, address) = match &self {
            Self::GeneralFailure
            | Self::ConnectionNotAllowed
            | Self::NetworkUnreachable
            | Self::HostUnreachable
            | Self::ConnectionRefused
            | Self::TTLExpired
            | Self::CommandNotSupported
            | Self::AddressTypeNotSupported => (self.as_u8(), Address::unspecified()),
            Self::Unassigned(code) => (*code, Address::unspecified()),
            Self::Success(address) => (self.as_u8(), *address),
        };

        bytes.put_u8(reply);
        bytes.put_u8(0x00);
        bytes.extend(address.to_bytes());

        bytes
    }

    #[rustfmt::skip]
    #[inline]
    fn as_u8(&self) -> u8 {
        match self {
            Self::Success(_)                 => Self::SOCKS5_REPLY_SUCCEEDED,
            Self::GeneralFailure             => Self::SOCKS5_REPLY_GENERAL_FAILURE,
            Self::ConnectionNotAllowed       => Self::SOCKS5_REPLY_CONNECTION_NOT_ALLOWED,
            Self::NetworkUnreachable         => Self::SOCKS5_REPLY_NETWORK_UNREACHABLE,
            Self::HostUnreachable            => Self::SOCKS5_REPLY_HOST_UNREACHABLE,
            Self::ConnectionRefused          => Self::SOCKS5_REPLY_CONNECTION_REFUSED,
            Self::TTLExpired                 => Self::SOCKS5_REPLY_TTL_EXPIRED,
            Self::CommandNotSupported        => Self::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
            Self::AddressTypeNotSupported    => Self::SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
            Self::Unassigned(code)           => *code
        }
    }
}
