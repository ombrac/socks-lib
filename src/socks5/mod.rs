use std::io::Result;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use bytes::{BufMut, BytesMut};
use tokio::io::AsyncReadExt;

use crate::{consts::*, Streamable, ToBytes};

// SOCKS5 const
#[rustfmt::skip]
pub mod consts {
    pub const SOCKS5_VERSION:                          u8 = 0x05;

    pub const SOCKS5_CMD_CONNECT:                      u8 = 0x01;
    pub const SOCKS5_CMD_BIND:                         u8 = 0x02;
    pub const SOCKS5_CMD_ASSOCIATE:                    u8 = 0x03;

    pub const SOCKS5_ADDRESS_TYPE_IPV4:                u8 = 0x01;
    pub const SOCKS5_ADDRESS_TYPE_DOMAIN_NAME:         u8 = 0x03;
    pub const SOCKS5_ADDRESS_TYPE_IPV6:                u8 = 0x04;

    pub const SOCKS5_REPLY_SUCCEEDED:                  u8 = 0x00;
    pub const SOCKS5_REPLY_GENERAL_FAILURE:            u8 = 0x01;
    pub const SOCKS5_REPLY_CONNECTION_NOT_ALLOWED:     u8 = 0x02;
    pub const SOCKS5_REPLY_NETWORK_UNREACHABLE:        u8 = 0x03;
    pub const SOCKS5_REPLY_HOST_UNREACHABLE:           u8 = 0x04;
    pub const SOCKS5_REPLY_CONNECTION_REFUSED:         u8 = 0x05;
    pub const SOCKS5_REPLY_TTL_EXPIRED:                u8 = 0x06;
    pub const SOCKS5_REPLY_COMMAND_NOT_SUPPORTED:      u8 = 0x07;
    pub const SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

#[derive(Debug, Clone, PartialEq)]
pub enum Method {
    NoAuthentication,
    GSSAPI,
    UsernamePassword,
    IanaAssigned(u8),
    ReservedPrivate(u8),
    NoAcceptableMethod,
}

impl Method {
    #[rustfmt::skip]
    pub fn as_u8(&self) -> u8 {
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
    pub fn from_u8(value: u8) -> Self {
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

impl Streamable for Vec<Method> {
    /// # Authentication Methods
    ///
    /// ## Stream
    /// ```text
    ///          +-----+----------+----------+
    ///          | VER | NMETHODS | METHODS  |
    ///          +-----+----------+----------+
    ///          |  1  |    1     | 1 to 255 |
    ///          +-----+----------+----------+
    /// ```
    async fn read<T>(stream: &mut T) -> Result<Self>
    where
        T: AsyncReadExt + Unpin + Send,
    {
        let mut buffer = [0u8; 2];
        stream.read_exact(&mut buffer).await?;

        let method_num = buffer[1];
        if method_num == 1 {
            let method = stream.read_u8().await?;
            return Ok(vec![Method::from_u8(method)]);
        }

        let mut methods = vec![0u8; method_num as usize];
        stream.read_exact(&mut methods).await?;

        let result = methods.into_iter().map(|e| Method::from_u8(e)).collect();

        Ok(result)
    }
}

impl ToBytes for Vec<Method> {
    fn to_bytes(&self) -> BytesMut {
        let mut bytes = BytesMut::new();

        bytes.put_u8(consts::SOCKS5_VERSION);
        bytes.put_u8(self.len() as u8);

        for e in self.iter() {
            bytes.put_u8(e.as_u8());
        }

        bytes
    }
}

impl Streamable for Method {
    /// # Method
    ///
    /// ## Stream
    /// ```text
    ///      +-----+--------+
    ///      | VER | METHOD |
    ///      +-----+--------+
    ///      |  1  |   1    |
    ///      +-----+--------+
    /// ```
    async fn read<T>(stream: &mut T) -> Result<Self>
    where
        T: AsyncReadExt + Unpin + Send,
    {
        let mut buffer = [0u8; 2];
        stream.read_exact(&mut buffer).await?;

        Ok(Self::from_u8(buffer[1]))
    }
}

impl ToBytes for Method {
    fn to_bytes(&self) -> BytesMut {
        let mut bytes = BytesMut::new();

        bytes.put_u8(consts::SOCKS5_VERSION);
        bytes.put_u8(self.as_u8());

        bytes
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Request {
    Bind(Address),
    Connect(Address),
    Associate(Address),
}

impl Streamable for Request {
    /// # Request
    ///
    /// ## Stream
    /// ```text
    ///      +-----+-----+-------+------+----------+----------+
    ///      | VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    ///      +-----+-----+-------+------+----------+----------+
    ///      |  1  |  1  | X'00' |  1   | Variable |    2     |
    ///      +-----+-----+-------+------+----------+----------+
    /// ```
    ///
    /// ## Where
    /// o  VER    protocol version: X'05'  
    /// o  CMD  
    ///    o  CONNECT X'01'  
    ///    o  BIND X'02'  
    ///    o  UDP ASSOCIATE X'03'  
    /// o  RSV    RESERVED  
    /// o  ATYP   address type of following address  
    ///    o  IP V4 address: X'01'  
    ///    o  DOMAINNAME: X'03'  
    ///    o  IP V6 address: X'04'  
    /// o  DST.ADDR       desired destination address  
    /// o  DST.PORT desired destination port in network octet  
    ///    order  
    ///
    async fn read<T>(stream: &mut T) -> Result<Self>
    where
        T: AsyncReadExt + Unpin + Send,
    {
        use std::io::{Error, ErrorKind};

        let mut buffer = [0u8; 3];
        stream.read_exact(&mut buffer).await?;

        let command = buffer[1];
        let address = Address::read(stream).await?;

        let result = match command {
            consts::SOCKS5_CMD_BIND => Request::Bind(address),
            consts::SOCKS5_CMD_CONNECT => Request::Connect(address),
            consts::SOCKS5_CMD_ASSOCIATE => Request::Associate(address),
            _command => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("unsupported socks request command {}", _command),
                ))
            }
        };

        Ok(result)
    }
}

impl ToBytes for Request {
    fn to_bytes(&self) -> BytesMut {
        let mut bytes = BytesMut::new();

        bytes.put_u8(consts::SOCKS5_VERSION);

        let address_bytes = match self {
            Self::Connect(address) => {
                bytes.put_u8(consts::SOCKS5_CMD_CONNECT);
                address.to_bytes()
            }
            Self::Bind(address) => {
                bytes.put_u8(consts::SOCKS5_CMD_BIND);
                address.to_bytes()
            }
            Self::Associate(address) => {
                bytes.put_u8(consts::SOCKS5_CMD_ASSOCIATE);
                address.to_bytes()
            }
        };

        bytes.put_u8(0x00);
        bytes.extend(address_bytes);

        bytes
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Address {
    IPv4(SocketAddrV4),
    IPv6(SocketAddrV6),
    Domain(String, u16),
}

impl Address {
    pub fn from_socket_address(address: SocketAddr) -> Self {
        match address {
            SocketAddr::V4(addr) => Self::IPv4(addr),
            SocketAddr::V6(addr) => Self::IPv6(addr),
        }
    }
}

impl Streamable for Address {
    /// # Address
    ///
    /// ## Stream
    /// ```text
    ///      +------+----------+----------+
    ///      | ATYP | DST.ADDR | DST.PORT |
    ///      +------+----------+----------+
    ///      |  1   | Variable |    2     |
    ///      +------+----------+----------+
    /// ```
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
    async fn read<T>(stream: &mut T) -> Result<Self>
    where
        T: AsyncReadExt + Unpin + Send,
    {
        use std::io::{Error, ErrorKind};
        use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

        let result = match stream.read_u8().await? {
            consts::SOCKS5_ADDRESS_TYPE_IPV4 => {
                let mut buffer = [0u8; IPV4_ADDRESS_LENGTH + PORT_LENGTH];
                stream.read_exact(&mut buffer).await?;

                let ip = Ipv4Addr::new(buffer[0], buffer[1], buffer[2], buffer[3]);
                let port = ((buffer[4] as u16) << 8) | (buffer[5] as u16);

                Address::IPv4(SocketAddrV4::new(ip, port))
            }

            consts::SOCKS5_ADDRESS_TYPE_IPV6 => {
                let mut buffer = [0u8; IPV6_ADDRESS_LENGTH + PORT_LENGTH];
                stream.read_exact(&mut buffer).await?;

                let ip = Ipv6Addr::new(
                    (buffer[0] as u16) << 8 | buffer[1] as u16,
                    (buffer[2] as u16) << 8 | buffer[3] as u16,
                    (buffer[4] as u16) << 8 | buffer[5] as u16,
                    (buffer[6] as u16) << 8 | buffer[7] as u16,
                    (buffer[8] as u16) << 8 | buffer[9] as u16,
                    (buffer[10] as u16) << 8 | buffer[11] as u16,
                    (buffer[12] as u16) << 8 | buffer[13] as u16,
                    (buffer[14] as u16) << 8 | buffer[15] as u16,
                );
                let port = ((buffer[16] as u16) << 8) | (buffer[17] as u16);

                Address::IPv6(SocketAddrV6::new(ip, port, 0, 0))
            }

            consts::SOCKS5_ADDRESS_TYPE_DOMAIN_NAME => {
                let domain_len = stream.read_u8().await? as usize;

                let mut buffer = vec![0u8; domain_len + PORT_LENGTH];
                stream.read_exact(&mut buffer).await?;

                let domain = std::str::from_utf8(&buffer[0..domain_len])
                    .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid domain name"))?;

                let port = ((buffer[domain_len] as u16) << 8) | (buffer[domain_len + 1] as u16);

                Address::Domain(domain.to_string(), port)
            }

            _address_type => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("unsupported socks request address type {}", _address_type),
                ))
            }
        };

        Ok(result)
    }
}

impl ToBytes for Address {
    fn to_bytes(&self) -> BytesMut {
        let mut bytes = BytesMut::new();

        match self {
            Self::Domain(domain, port) => {
                let domain_bytes = domain.as_bytes();
                bytes.put_u8(consts::SOCKS5_ADDRESS_TYPE_DOMAIN_NAME);
                bytes.put_u8(domain_bytes.len() as u8);
                bytes.extend_from_slice(domain_bytes);
                bytes.extend_from_slice(&port.to_be_bytes());
            }
            Self::IPv4(addr) => {
                bytes.put_u8(consts::SOCKS5_ADDRESS_TYPE_IPV4);
                bytes.extend_from_slice(&addr.ip().octets());
                bytes.extend_from_slice(&addr.port().to_be_bytes());
            }
            Self::IPv6(addr) => {
                bytes.put_u8(consts::SOCKS5_ADDRESS_TYPE_IPV6);
                bytes.extend_from_slice(&addr.ip().octets());
                bytes.extend_from_slice(&addr.port().to_be_bytes());
            }
        }

        bytes
    }
}

#[derive(Debug, Clone)]
pub enum Response {
    Success(Address),
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

impl Response {
    pub fn unspecified_success() -> Self {
        use std::net::{Ipv4Addr, SocketAddrV4};
        use std::sync::OnceLock;

        static ADDRESS: OnceLock<Address> = OnceLock::new();
        let unspecified_address =
            ADDRESS.get_or_init(|| Address::IPv4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)));

        Self::Success(unspecified_address.clone())
    }
}

impl Streamable for Response {
    /// # Response
    ///
    /// ## Stream
    ///
    /// ```text
    ///      +-----+-----+-------+------+----------+----------+
    ///      | VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    ///      +-----+-----+-------+------+----------+----------+
    ///      |  1  |  1  | X'00' |  1   | Variable |    2     |
    ///      +-----+-----+-------+------+----------+----------+
    /// ```
    async fn read<T>(stream: &mut T) -> Result<Self>
    where
        T: AsyncReadExt + Unpin + Send,
    {
        let mut buffer = [0u8; 3];
        stream.read_exact(&mut buffer).await?;

        let reply = buffer[1];
        let address = Address::read(stream).await?;

        #[rustfmt::skip]
        let result = match reply {
            consts::SOCKS5_REPLY_SUCCEEDED                  => Self::Success(address),
            consts::SOCKS5_REPLY_GENERAL_FAILURE            => Self::GeneralFailure,
            consts::SOCKS5_REPLY_CONNECTION_NOT_ALLOWED     => Self::ConnectionNotAllowed,
            consts::SOCKS5_REPLY_NETWORK_UNREACHABLE        => Self::NetworkUnreachable,
            consts::SOCKS5_REPLY_HOST_UNREACHABLE           => Self::HostUnreachable,
            consts::SOCKS5_REPLY_CONNECTION_REFUSED         => Self::ConnectionRefused,
            consts::SOCKS5_REPLY_TTL_EXPIRED                => Self::TTLExpired,
            consts::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED      => Self::CommandNotSupported,
            consts::SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED => Self::AddressTypeNotSupported,

            _code => Self::Unassigned(_code),
        };

        Ok(result)
    }
}

impl ToBytes for Response {
    fn to_bytes(&self) -> BytesMut {
        use std::net::{Ipv4Addr, SocketAddrV4};
        use std::sync::OnceLock;

        static ADDRESS: OnceLock<Address> = OnceLock::new();
        let unspecified_address =
            ADDRESS.get_or_init(|| Address::IPv4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)));

        let mut bytes = BytesMut::new();

        let (reply, address) = match &self {
            Self::GeneralFailure
            | Self::ConnectionNotAllowed
            | Self::NetworkUnreachable
            | Self::HostUnreachable
            | Self::ConnectionRefused
            | Self::TTLExpired
            | Self::CommandNotSupported
            | Self::AddressTypeNotSupported
            | Self::Unassigned(_) => (self.as_u8(), unspecified_address),
            Self::Success(address) => (self.as_u8(), address),
        };

        bytes.put_u8(consts::SOCKS5_VERSION);
        bytes.put_u8(reply);
        bytes.put_u8(0x00);
        bytes.extend(address.to_bytes());

        bytes
    }
}

impl Response {
    #[rustfmt::skip]
    fn as_u8(&self) -> u8 {
        match self {
            Self::Success(_)                 => consts::SOCKS5_REPLY_SUCCEEDED,
            Self::GeneralFailure             => consts::SOCKS5_REPLY_GENERAL_FAILURE,
            Self::ConnectionNotAllowed       => consts::SOCKS5_REPLY_CONNECTION_NOT_ALLOWED,
            Self::NetworkUnreachable         => consts::SOCKS5_REPLY_NETWORK_UNREACHABLE,
            Self::HostUnreachable            => consts::SOCKS5_REPLY_HOST_UNREACHABLE,
            Self::ConnectionRefused          => consts::SOCKS5_REPLY_CONNECTION_REFUSED,
            Self::TTLExpired                 => consts::SOCKS5_REPLY_TTL_EXPIRED,
            Self::CommandNotSupported        => consts::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
            Self::AddressTypeNotSupported    => consts::SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
            Self::Unassigned(code)           => *code
        }
    }
}

#[derive(Debug)]
pub struct UdpPacket {
    pub frag: u8,
    pub address: Address,
    pub data: BytesMut,
}

impl UdpPacket {
    pub fn un_frag(address: Address, data: BytesMut) -> Self {
        Self {
            frag: 0,
            address,
            data,
        }
    }
}

impl Streamable for UdpPacket {
    /// # UDP Packet
    ///
    /// ## Stream
    ///
    /// ```text
    ///      +-----+------+------+----------+----------+----------+
    ///      | RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
    ///      +-----+------+------+----------+----------+----------+
    ///      |  2  |  1   |  1   | Variable |    2     | Variable |
    ///      +-----+------+------+----------+----------+----------+
    /// ```
    async fn read<T>(stream: &mut T) -> Result<Self>
    where
        T: AsyncReadExt + Unpin + Send,
    {
        let mut buffer = [0u8; 3];
        stream.read_exact(&mut buffer).await?;

        let frag = buffer[2];
        let address = Address::read(stream).await?;

        let mut data = Vec::new();
        stream.read_to_end(&mut data).await?;

        let data = BytesMut::from(data.as_slice());

        Ok(Self {
            frag,
            address,
            data,
        })
    }
}

impl ToBytes for UdpPacket {
    fn to_bytes(&self) -> BytesMut {
        let mut bytes = BytesMut::new();

        bytes.put_u8(0x00);
        bytes.put_u8(0x00);

        bytes.put_u8(self.frag);
        bytes.extend(self.address.to_bytes());
        bytes.extend_from_slice(&self.data);
        bytes
    }
}