pub mod server;

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::LazyLock;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};

/// # Method
///
/// ```text
///  +--------+
///  | METHOD |
///  +--------+
///  |   1    |
///  +--------+
/// ```
///
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Method {
    NoAuthentication,
    GSSAPI,
    UsernamePassword,
    IanaAssigned(u8),
    ReservedPrivate(u8),
    NoAcceptableMethod,
}

impl Method {
    // pub async fn from_async_read<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {}
    // pub fn from_bytes<B: Buf>(buf: &mut B) -> io::Result<Self> {}
    // pub fn to_bytes() {}

    #[rustfmt::skip]
    #[inline]
    fn as_u8(&self) -> u8 {
        match self {
            Self::NoAuthentication            => 0x00,
            Self::GSSAPI                      => 0x01,
            Self::UsernamePassword            => 0x03,
            Self::IanaAssigned(value)         => *value,
            Self::ReservedPrivate(value)      => *value,
            Self::NoAcceptableMethod          => 0xFF,
        }
    }

    #[rustfmt::skip]
    #[inline]
    fn from_u8(value: u8) -> Self {
        match value {
            0x00        => Self::NoAuthentication,
            0x01        => Self::GSSAPI,
            0x02        => Self::UsernamePassword,
            0x03..=0x7F => Self::IanaAssigned(value),
            0x80..=0xFE => Self::ReservedPrivate(value),
            0xFF        => Self::NoAcceptableMethod,
        }
    }
}

/// # Request
///
/// ```
///  +-----+-------+------+----------+----------+
///  | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
///  +-----+-------+------+----------+----------+
///  |  1  | X'00' |  1   | Variable |    2     |
///  +-----+-------+------+----------+----------+
/// ```
///
#[derive(Debug, Clone, PartialEq)]
pub enum Request {
    Bind(Address),
    Connect(Address),
    Associate(Address),
}

#[rustfmt::skip]
impl Request {
    const SOCKS5_CMD_CONNECT:   u8 = 0x01;
    const SOCKS5_CMD_BIND:      u8 = 0x02;
    const SOCKS5_CMD_ASSOCIATE: u8 = 0x03;
}

impl Request {
    pub async fn from_async_read<R: AsyncRead + Unpin>(
        reader: &mut BufReader<R>,
    ) -> io::Result<Self> {
        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf).await?;

        let command = buf[0];

        let request = match command {
            Self::SOCKS5_CMD_BIND => Self::Bind(Address::from_async_read(reader).await?),
            Self::SOCKS5_CMD_CONNECT => Self::Connect(Address::from_async_read(reader).await?),
            Self::SOCKS5_CMD_ASSOCIATE => Self::Associate(Address::from_async_read(reader).await?),
            command => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid request command: {}", command),
                ))
            }
        };

        Ok(request)
    }
}

/// # Address
///
/// ```text
///  +------+----------+----------+
///  | ATYP | DST.ADDR | DST.PORT |
///  +------+----------+----------+
///  |  1   | Variable |    2     |
///  +------+----------+----------+
/// ```
///
/// ## DST.ADDR BND.ADDR
///   In an address field (DST.ADDR, BND.ADDR), the ATYP field specifies
///   the type of address contained within the field:
///   
/// o ATYP: X'01'
///   the address is a version-4 IP address, with a length of 4 octets
///   
/// o ATYP: X'03'
///   the address field contains a fully-qualified domain name.  The first
///   octet of the address field contains the number of octets of name that
///   follow, there is no terminating NUL octet.
///   
/// o ATYP: X'04'  
///   the address is a version-6 IP address, with a length of 16 octets.
///
#[derive(Debug, Clone, PartialEq)]
pub enum Address {
    IPv4(SocketAddrV4),
    IPv6(SocketAddrV6),
    Domain(Domain, u16),
}

static UNSPECIFIED_ADDRESS: LazyLock<Address> =
    LazyLock::new(|| Address::IPv4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)));

#[rustfmt::skip]
impl Address {
    const PORT_LENGTH:         usize = 2;
    const IPV4_ADDRESS_LENGTH: usize = 4;
    const IPV6_ADDRESS_LENGTH: usize = 16;

    const SOCKS5_ADDRESS_TYPE_IPV4:        u8 = 0x01;
    const SOCKS5_ADDRESS_TYPE_DOMAIN_NAME: u8 = 0x03;
    const SOCKS5_ADDRESS_TYPE_IPV6:        u8 = 0x04;
}

impl Address {
    #[inline]
    pub fn unspecified() -> &'static Self {
        &UNSPECIFIED_ADDRESS
    }

    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(addr) => Self::IPv4(addr),
            SocketAddr::V6(addr) => Self::IPv6(addr),
        }
    }

    pub async fn from_async_read<R: AsyncRead + Unpin>(
        reader: &mut BufReader<R>,
    ) -> io::Result<Self> {
        let address_type = reader.read_u8().await?;

        match address_type {
            Self::SOCKS5_ADDRESS_TYPE_IPV4 => {
                let mut buf = [0u8; Self::IPV4_ADDRESS_LENGTH + Self::PORT_LENGTH];
                reader.read_exact(&mut buf).await?;

                let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let port = u16::from_be_bytes([buf[4], buf[5]]);

                Ok(Address::IPv4(SocketAddrV4::new(ip, port)))
            }

            Self::SOCKS5_ADDRESS_TYPE_IPV6 => {
                let mut buf = [0u8; Self::IPV6_ADDRESS_LENGTH + Self::PORT_LENGTH];
                reader.read_exact(&mut buf).await?;

                let ip = Ipv6Addr::from([
                    buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
                    buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
                ]);
                let port = u16::from_be_bytes([buf[16], buf[17]]);

                Ok(Address::IPv6(SocketAddrV6::new(ip, port, 0, 0)))
            }

            Self::SOCKS5_ADDRESS_TYPE_DOMAIN_NAME => {
                let domain_len = reader.read_u8().await? as usize;

                let mut buf = vec![0u8; domain_len + Self::PORT_LENGTH];
                reader.read_exact(&mut buf).await?;

                let domain = Bytes::copy_from_slice(&buf[..domain_len]);
                let port = u16::from_be_bytes([buf[domain_len], buf[domain_len + 1]]);

                Ok(Address::Domain(Domain(domain), port))
            }

            n => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid address type: {}", n),
            )),
        }
    }

    pub fn from_bytes<B: Buf>(buf: &mut B) -> io::Result<Self> {
        if buf.remaining() < 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Insufficient data for address",
            ));
        }

        let address_type = buf.get_u8();

        match address_type {
            Self::SOCKS5_ADDRESS_TYPE_IPV4 => {
                if buf.remaining() < Self::IPV4_ADDRESS_LENGTH + Self::PORT_LENGTH {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Insufficient data for IPv4 address",
                    ));
                }

                let mut ip = [0u8; Self::IPV4_ADDRESS_LENGTH];
                buf.copy_to_slice(&mut ip);

                let port = buf.get_u16();

                Ok(Address::IPv4(SocketAddrV4::new(Ipv4Addr::from(ip), port)))
            }

            Self::SOCKS5_ADDRESS_TYPE_IPV6 => {
                if buf.remaining() < Self::IPV6_ADDRESS_LENGTH + Self::PORT_LENGTH {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Insufficient data for IPv6 address",
                    ));
                }

                let mut ip = [0u8; Self::IPV6_ADDRESS_LENGTH];
                buf.copy_to_slice(&mut ip);

                let port = buf.get_u16();

                Ok(Address::IPv6(SocketAddrV6::new(
                    Ipv6Addr::from(ip),
                    port,
                    0,
                    0,
                )))
            }

            Self::SOCKS5_ADDRESS_TYPE_DOMAIN_NAME => {
                if buf.remaining() < 1 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Insufficient data for domain length",
                    ));
                }

                let domain_len = buf.get_u8() as usize;

                if buf.remaining() < domain_len + Self::PORT_LENGTH {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Insufficient data for domain name",
                    ));
                }

                let mut domain = vec![0u8; domain_len];
                buf.copy_to_slice(&mut domain);

                let port = buf.get_u16();

                Ok(Address::Domain(Domain(Bytes::from(domain)), port))
            }

            n => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid address type: {}", n),
            )),
        }
    }

    #[inline]
    pub fn to_bytes(&self) -> Bytes {
        let mut bytes = BytesMut::new();

        match self {
            Self::Domain(domain, port) => {
                let domain_bytes = domain.as_bytes();
                bytes.put_u8(Self::SOCKS5_ADDRESS_TYPE_DOMAIN_NAME);
                bytes.put_u8(domain_bytes.len() as u8);
                bytes.extend_from_slice(domain_bytes);
                bytes.extend_from_slice(&port.to_be_bytes());
            }
            Self::IPv4(addr) => {
                bytes.put_u8(Self::SOCKS5_ADDRESS_TYPE_IPV4);
                bytes.extend_from_slice(&addr.ip().octets());
                bytes.extend_from_slice(&addr.port().to_be_bytes());
            }
            Self::IPv6(addr) => {
                bytes.put_u8(Self::SOCKS5_ADDRESS_TYPE_IPV6);
                bytes.extend_from_slice(&addr.ip().octets());
                bytes.extend_from_slice(&addr.port().to_be_bytes());
            }
        }

        bytes.freeze()
    }

    #[inline]
    pub fn port(&self) -> u16 {
        match self {
            Self::IPv4(addr) => addr.port(),
            Self::IPv6(addr) => addr.port(),
            Self::Domain(_, port) => *port,
        }
    }

    #[inline]
    pub fn as_str(&self) -> String {
        match self {
            Self::IPv4(addr) => addr.to_string(),
            Self::IPv6(addr) => addr.to_string(),
            Self::Domain(domain, port) => {
                format!("{}:{}", domain.domain_str().unwrap().to_string(), port)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Domain(Bytes);

impl Domain {
    #[inline]
    pub fn domain_str(&self) -> io::Result<&str> {
        use std::str::from_utf8;

        from_utf8(&self.0).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8"))
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[inline]
    pub fn to_bytes(self) -> Bytes {
        self.0
    }
}

impl AsRef<[u8]> for Domain {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

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

/// # UDP Packet
///
///
/// ```text
///  +-----+------+------+----------+----------+----------+
///  | RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
///  +-----+------+------+----------+----------+----------+
///  |  2  |  1   |  1   | Variable |    2     | Variable |
///  +-----+------+------+----------+----------+----------+
/// ```
///
#[derive(Debug)]
pub struct UdpPacket {
    pub frag: u8,
    pub address: Address,
    pub data: Bytes,
}

impl UdpPacket {
    pub fn from_bytes<B: Buf>(_buf: &mut B) -> io::Result<Self> {
        todo!()
    }

    pub fn to_bytes(&self) -> Bytes {
        let mut bytes = BytesMut::new();

        bytes.put_u8(0x00);
        bytes.put_u8(0x00);

        bytes.put_u8(self.frag);
        bytes.extend(self.address.to_bytes());
        bytes.extend_from_slice(&self.data);

        bytes.freeze()
    }

    pub fn un_frag(address: Address, data: Bytes) -> Self {
        Self {
            frag: 0,
            address,
            data,
        }
    }
}

pub struct Stream<T> {
    version: u8,
    from: SocketAddr,
    inner: BufReader<T>,
}

impl<T> Stream<T> {
    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn from_addr(&self) -> SocketAddr {
        self.from
    }
}

mod async_impl {
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncWrite};

    use super::Stream;

    impl<T> AsyncRead for Stream<T>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            AsyncRead::poll_read(Pin::new(&mut self.inner.get_mut()), cx, buf)
        }
    }

    impl<T> AsyncWrite for Stream<T>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            AsyncWrite::poll_write(Pin::new(&mut self.inner.get_mut()), cx, buf)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            AsyncWrite::poll_flush(Pin::new(&mut self.inner.get_mut()), cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            AsyncWrite::poll_shutdown(Pin::new(&mut self.inner.get_mut()), cx)
        }
    }
}
