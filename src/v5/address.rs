use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::LazyLock;

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::io::{AsyncRead, AsyncReadExt};

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
    pub const PORT_LENGTH:         usize = 2;
    pub const IPV4_ADDRESS_LENGTH: usize = 4;
    pub const IPV6_ADDRESS_LENGTH: usize = 16;

    pub const SOCKS5_ADDRESS_TYPE_IPV4:        u8 = 0x01;
    pub const SOCKS5_ADDRESS_TYPE_DOMAIN_NAME: u8 = 0x03;
    pub const SOCKS5_ADDRESS_TYPE_IPV6:        u8 = 0x04;
}

impl Address {
    #[inline]
    pub fn unspecified() -> &'static Self {
        &UNSPECIFIED_ADDRESS
    }

    pub async fn from_async_read<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
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

    pub async fn to_socket_addr(self) -> io::Result<SocketAddr> {
        use tokio::net::lookup_host;

        match self {
            Address::IPv4(addr) => Ok(SocketAddr::V4(addr)),
            Address::IPv6(addr) => Ok(SocketAddr::V6(addr)),
            Address::Domain(domain, port) => {
                let domain = domain.format_as_str();

                lookup_host((domain, port))
                    .await?
                    .next()
                    .ok_or(io::Error::other(format!(
                        "Failed to resolve domain {}",
                        domain
                    )))
            }
        }
    }
}

impl From<SocketAddr> for Address {
    #[inline]
    fn from(value: SocketAddr) -> Self {
        match value {
            SocketAddr::V4(addr) => Self::IPv4(addr),
            SocketAddr::V6(addr) => Self::IPv6(addr),
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Domain(domain, port) => format!("{}:{}", domain.format_as_str(), port),
            Self::IPv4(addr) => addr.to_string(),
            Self::IPv6(addr) => addr.to_string(),
        };

        write!(f, "{value}")
    }
}

impl TryFrom<&str> for Address {
    type Error = io::Error;

    #[inline]
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        use std::str::FromStr;

        if let Ok(ipv4_addr) = SocketAddrV4::from_str(value) {
            return Ok(Address::IPv4(ipv4_addr));
        }

        if let Ok(addr) = SocketAddrV6::from_str(value) {
            return Ok(Address::IPv6(addr));
        }

        if let Some((domain, port_str)) = value.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                if !domain.is_empty() {
                    return Ok(Address::Domain(Domain::try_from(domain)?, port));
                }
            }
        }

        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid address format: {}", value),
        ))
    }
}

impl TryFrom<String> for Address {
    type Error = io::Error;

    #[inline]
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Address::try_from(value.as_str())
    }
}

// ===== Domain =====
#[derive(Debug, Clone, PartialEq)]
pub struct Domain(Bytes);

impl Domain {
    const MAX_LENGTH: usize = 254;

    #[inline]
    pub fn from_bytes(bytes: Bytes) -> io::Result<Self> {
        if bytes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Domain is empty",
            ));
        }

        let domain_str = std::str::from_utf8(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        if domain_str.len() > Self::MAX_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Punycode domain exceeds maximum length",
            ));
        }

        Ok(Self(bytes))
    }

    #[inline]
    pub fn from_string(value: String) -> io::Result<Self> {
        Self::from_bytes(value.into())
    }

    #[inline]
    pub fn format_as_str(&self) -> &str {
        use std::str::from_utf8;

        from_utf8(&self.0).expect("Invalid UTF-8")
    }

    #[inline]
    pub fn as_bytes(&self) -> &Bytes {
        &self.0
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl TryFrom<&[u8]> for Domain {
    type Error = io::Error;

    #[inline]
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(Bytes::copy_from_slice(value))
    }
}

impl TryFrom<&str> for Domain {
    type Error = io::Error;

    #[inline]
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_bytes(Bytes::copy_from_slice(value.as_bytes()))
    }
}

impl TryFrom<String> for Domain {
    type Error = io::Error;

    #[inline]
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_string(value)
    }
}

impl TryFrom<Bytes> for Domain {
    type Error = io::Error;

    #[inline]
    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}

impl AsRef<[u8]> for Domain {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::BufReader;

    use super::*;

    use std::{
        io::Cursor,
        net::{Ipv4Addr, Ipv6Addr},
    };

    #[test]
    fn test_ipv4_serialization() {
        let addr = Address::IPv4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080));
        let bytes = addr.to_bytes();
        let mut buf = &bytes[..];
        let parsed = Address::from_bytes(&mut buf).unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_ipv6_serialization() {
        let addr = Address::IPv6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8080, 0, 0));
        let bytes = addr.to_bytes();
        let mut buf = &bytes[..];
        let parsed = Address::from_bytes(&mut buf).unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_domain_serialization() {
        let domain = Domain::try_from("example.com").unwrap();
        let addr = Address::Domain(domain, 8080);
        let bytes = addr.to_bytes();
        let mut buf = &bytes[..];

        let parsed = Address::from_bytes(&mut buf).unwrap();

        if let Address::Domain(d, p) = parsed {
            assert_eq!(d.format_as_str(), "example.com");
            assert_eq!(p, 8080);
        } else {
            panic!("Parsed address is not Domain type");
        }
    }

    #[test]
    fn test_invalid_atyp() {
        let mut buf = bytes::BytesMut::new();
        buf.put_u8(0x04);
        let mut buf = buf.freeze();
        let result = Address::from_bytes(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_domain_too_long() {
        let result = Domain::try_from(vec![b'a'; 255].as_slice());
        assert!(result.is_err())
    }

    #[tokio::test]
    async fn test_domain_resolution() {
        let domain = Domain::try_from("localhost").unwrap();
        let addr = Address::Domain(domain, 8080);
        let socket_addr = addr.to_socket_addr().await.unwrap();
        assert!(socket_addr.port() == 8080);
    }

    #[test]
    fn test_domain_utf8_error() {
        let result = Domain::from_bytes(Bytes::copy_from_slice(vec![0xff, 0xfe].as_slice()));
        assert!(result.is_err())
    }

    #[test]
    fn test_socket_addr_conversion() {
        let socket_v4 = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080);
        let addr: Address = SocketAddr::V4(socket_v4).into();
        assert!(matches!(addr, Address::IPv4(_)));

        let socket_v6 = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8080, 0, 0);
        let addr: Address = SocketAddr::V6(socket_v6).into();
        assert!(matches!(addr, Address::IPv6(_)));
    }

    #[tokio::test]
    async fn test_address_unspecified() {
        let unspecified = Address::unspecified();
        match unspecified {
            Address::IPv4(addr) => {
                assert_eq!(addr.ip(), &Ipv4Addr::UNSPECIFIED);
                assert_eq!(addr.port(), 0);
            }
            _ => panic!("Unspecified address should be IPv4"),
        }
    }

    #[tokio::test]
    async fn test_address_from_socket_addr_ipv4() {
        let socket = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080));
        let address = Address::from(socket);

        match address {
            Address::IPv4(addr) => {
                assert_eq!(addr.ip().octets(), [127, 0, 0, 1]);
                assert_eq!(addr.port(), 8080);
            }
            _ => panic!("Should be IPv4 address"),
        }
    }

    #[tokio::test]
    async fn test_address_from_socket_addr_ipv6() {
        let socket = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
            8080,
            0,
            0,
        ));
        let address = Address::from(socket);

        match address {
            Address::IPv6(addr) => {
                assert_eq!(
                    addr.ip().octets(),
                    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
                );
                assert_eq!(addr.port(), 8080);
            }
            _ => panic!("Should be IPv6 address"),
        }
    }

    #[tokio::test]
    async fn test_address_to_bytes_ipv4() {
        let addr = Address::IPv4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 80));
        let bytes = addr.to_bytes();

        assert_eq!(bytes[0], Address::SOCKS5_ADDRESS_TYPE_IPV4);
        assert_eq!(bytes[1..5], [192, 168, 1, 1]);
        assert_eq!(bytes[5..7], [0, 80]); // Port 80 in big-endian
    }

    #[tokio::test]
    async fn test_address_to_bytes_ipv6() {
        let addr = Address::IPv6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            443,
            0,
            0,
        ));
        let bytes = addr.to_bytes();

        assert_eq!(bytes[0], Address::SOCKS5_ADDRESS_TYPE_IPV6);
        assert_eq!(
            bytes[1..17],
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert_eq!(bytes[17..19], [1, 187]); // Port 443 in big-endian
    }

    #[tokio::test]
    async fn test_address_to_bytes_domain() {
        let domain = Domain(Bytes::from("example.com"));
        let addr = Address::Domain(domain, 8080);
        let bytes = addr.to_bytes();

        assert_eq!(bytes[0], Address::SOCKS5_ADDRESS_TYPE_DOMAIN_NAME);
        assert_eq!(bytes[1], 11); // Length of "example.com"
        assert_eq!(&bytes[2..13], b"example.com");
        assert_eq!(bytes[13..15], [31, 144]); // Port 8080 in big-endian
    }

    #[tokio::test]
    async fn test_address_from_bytes_ipv4() {
        let mut buffer = BytesMut::new();
        buffer.put_u8(Address::SOCKS5_ADDRESS_TYPE_IPV4);
        buffer.put_slice(&[192, 168, 1, 1]); // IP
        buffer.put_u16(80); // Port

        let mut bytes = buffer.freeze();
        let addr = Address::from_bytes(&mut bytes).unwrap();

        match addr {
            Address::IPv4(socket_addr) => {
                assert_eq!(socket_addr.ip().octets(), [192, 168, 1, 1]);
                assert_eq!(socket_addr.port(), 80);
            }
            _ => panic!("Should be IPv4 address"),
        }
    }

    #[tokio::test]
    async fn test_address_from_bytes_ipv6() {
        let mut buffer = BytesMut::new();
        buffer.put_u8(Address::SOCKS5_ADDRESS_TYPE_IPV6);
        buffer.put_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // IPv6
        buffer.put_u16(443); // Port

        let mut bytes = buffer.freeze();
        let addr = Address::from_bytes(&mut bytes).unwrap();

        match addr {
            Address::IPv6(socket_addr) => {
                assert_eq!(
                    socket_addr.ip().octets(),
                    [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
                );
                assert_eq!(socket_addr.port(), 443);
            }
            _ => panic!("Should be IPv6 address"),
        }
    }

    #[tokio::test]
    async fn test_address_from_bytes_domain() {
        let mut buffer = BytesMut::new();
        buffer.put_u8(Address::SOCKS5_ADDRESS_TYPE_DOMAIN_NAME);
        buffer.put_u8(11); // Length of domain name
        buffer.put_slice(b"example.com"); // Domain name
        buffer.put_u16(8080); // Port

        let mut bytes = buffer.freeze();
        let addr = Address::from_bytes(&mut bytes).unwrap();

        match addr {
            Address::Domain(domain, port) => {
                assert_eq!(**domain.as_bytes(), *b"example.com");
                assert_eq!(port, 8080);
            }
            _ => panic!("Should be domain address"),
        }
    }

    #[tokio::test]
    async fn test_address_from_async_read_ipv4() {
        let mut buffer = BytesMut::new();
        buffer.put_u8(Address::SOCKS5_ADDRESS_TYPE_IPV4);
        buffer.put_slice(&[192, 168, 1, 1]); // IP
        buffer.put_u16(80); // Port

        let bytes = buffer.freeze();
        let mut cursor = Cursor::new(bytes);
        let mut reader = BufReader::new(&mut cursor);

        let addr = Address::from_async_read(&mut reader).await.unwrap();

        match addr {
            Address::IPv4(socket_addr) => {
                assert_eq!(socket_addr.ip().octets(), [192, 168, 1, 1]);
                assert_eq!(socket_addr.port(), 80);
            }
            _ => panic!("Should be IPv4 address"),
        }
    }

    #[tokio::test]
    async fn test_address_from_async_read_ipv6() {
        let mut buffer = BytesMut::new();
        buffer.put_u8(Address::SOCKS5_ADDRESS_TYPE_IPV6);
        buffer.put_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // IPv6
        buffer.put_u16(443); // Port

        let bytes = buffer.freeze();
        let mut cursor = Cursor::new(bytes);
        let mut reader = BufReader::new(&mut cursor);

        let addr = Address::from_async_read(&mut reader).await.unwrap();

        match addr {
            Address::IPv6(socket_addr) => {
                assert_eq!(
                    socket_addr.ip().octets(),
                    [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
                );
                assert_eq!(socket_addr.port(), 443);
            }
            _ => panic!("Should be IPv6 address"),
        }
    }

    #[tokio::test]
    async fn test_address_from_async_read_domain() {
        let mut buffer = BytesMut::new();
        buffer.put_u8(Address::SOCKS5_ADDRESS_TYPE_DOMAIN_NAME);
        buffer.put_u8(11); // Length of domain name
        buffer.put_slice(b"example.com"); // Domain name
        buffer.put_u16(8080); // Port

        let bytes = buffer.freeze();
        let mut cursor = Cursor::new(bytes);
        let mut reader = BufReader::new(&mut cursor);

        let addr = Address::from_async_read(&mut reader).await.unwrap();

        match addr {
            Address::Domain(domain, port) => {
                assert_eq!(**domain.as_bytes(), *b"example.com");
                assert_eq!(port, 8080);
            }
            _ => panic!("Should be domain address"),
        }
    }

    #[tokio::test]
    async fn test_address_from_bytes_invalid_type() {
        let mut buffer = BytesMut::new();
        buffer.put_u8(0xFF); // Invalid address type

        let mut bytes = buffer.freeze();
        let result = Address::from_bytes(&mut bytes);

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_address_from_bytes_insufficient_data() {
        // IPv4 with incomplete data
        let mut buffer = BytesMut::new();
        buffer.put_u8(Address::SOCKS5_ADDRESS_TYPE_IPV4);
        buffer.put_slice(&[192, 168]); // Incomplete IP

        let mut bytes = buffer.freeze();
        let result = Address::from_bytes(&mut bytes);

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_address_port() {
        let addr1 = Address::IPv4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080));
        assert_eq!(addr1.port(), 8080);

        let addr2 = Address::IPv6(SocketAddrV6::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
            443,
            0,
            0,
        ));
        assert_eq!(addr2.port(), 443);

        let addr3 = Address::Domain(Domain(Bytes::from("example.com")), 80);
        assert_eq!(addr3.port(), 80);
    }

    #[tokio::test]
    async fn test_address_format_as_string() {
        let addr1 = Address::IPv4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080));
        assert_eq!(addr1.to_string(), "127.0.0.1:8080");

        let addr2 = Address::IPv6(SocketAddrV6::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
            443,
            0,
            0,
        ));
        assert_eq!(addr2.to_string(), "[::1]:443");

        // This test assumes Domain::domain_str() returns Ok with the domain string
        let addr3 = Address::Domain(Domain(Bytes::from("example.com")), 80);
        assert_eq!(addr3.to_string(), "example.com:80");
    }
}
