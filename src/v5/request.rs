use crate::io::{self, AsyncRead, AsyncReadExt};
use crate::v5::Address;

/// # Request
///
/// ```text
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
    pub async fn from_async_read<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
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
                ));
            }
        };

        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use crate::v5::{Address, Request};

    use bytes::{BufMut, BytesMut};
    use std::io::Cursor;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn test_request_from_async_read_connect_ipv4() {
        let mut buffer = BytesMut::new();

        // Command + Reserved
        buffer.put_u8(Request::SOCKS5_CMD_CONNECT);
        buffer.put_u8(0x00); // Reserved

        // Address type + Address + Port
        buffer.put_u8(Address::SOCKS5_ADDRESS_TYPE_IPV4);
        buffer.put_slice(&[192, 168, 1, 1]); // IP
        buffer.put_u16(80); // Port

        let bytes = buffer.freeze();
        let mut cursor = Cursor::new(bytes);
        let mut reader = BufReader::new(&mut cursor);

        let request = Request::from_async_read(&mut reader).await.unwrap();

        match request {
            Request::Connect(addr) => match addr {
                Address::IPv4(socket_addr) => {
                    assert_eq!(socket_addr.ip().octets(), [192, 168, 1, 1]);
                    assert_eq!(socket_addr.port(), 80);
                }
                _ => panic!("Should be IPv4 address"),
            },
            _ => panic!("Should be Connect request"),
        }
    }

    #[tokio::test]
    async fn test_request_from_async_read_bind_ipv6() {
        let mut buffer = BytesMut::new();

        // Command + Reserved
        buffer.put_u8(Request::SOCKS5_CMD_BIND);
        buffer.put_u8(0x00); // Reserved

        // Address type + Address + Port
        buffer.put_u8(Address::SOCKS5_ADDRESS_TYPE_IPV6);
        buffer.put_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // IPv6
        buffer.put_u16(443); // Port

        let bytes = buffer.freeze();
        let mut cursor = Cursor::new(bytes);
        let mut reader = BufReader::new(&mut cursor);

        let request = Request::from_async_read(&mut reader).await.unwrap();

        match request {
            Request::Bind(addr) => match addr {
                Address::IPv6(socket_addr) => {
                    assert_eq!(
                        socket_addr.ip().octets(),
                        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
                    );
                    assert_eq!(socket_addr.port(), 443);
                }
                _ => panic!("Should be IPv6 address"),
            },
            _ => panic!("Should be Bind request"),
        }
    }

    #[tokio::test]
    async fn test_request_from_async_read_associate_domain() {
        let mut buffer = BytesMut::new();

        // Command + Reserved
        buffer.put_u8(Request::SOCKS5_CMD_ASSOCIATE);
        buffer.put_u8(0x00); // Reserved

        // Address type + Address + Port
        buffer.put_u8(Address::SOCKS5_ADDRESS_TYPE_DOMAIN_NAME);
        buffer.put_u8(11); // Length of domain name
        buffer.put_slice(b"example.com"); // Domain name
        buffer.put_u16(8080); // Port

        let bytes = buffer.freeze();
        let mut cursor = Cursor::new(bytes);
        let mut reader = BufReader::new(&mut cursor);

        let request = Request::from_async_read(&mut reader).await.unwrap();

        match request {
            Request::Associate(addr) => match addr {
                Address::Domain(domain, port) => {
                    assert_eq!(**domain.as_bytes(), *b"example.com");
                    assert_eq!(port, 8080);
                }
                _ => panic!("Should be domain address"),
            },
            _ => panic!("Should be Associate request"),
        }
    }

    #[tokio::test]
    async fn test_request_from_async_read_invalid_command() {
        let mut buffer = BytesMut::new();

        // Invalid Command + Reserved
        buffer.put_u8(0xFF); // Invalid command
        buffer.put_u8(0x00); // Reserved

        let bytes = buffer.freeze();
        let mut cursor = Cursor::new(bytes);
        let mut reader = BufReader::new(&mut cursor);

        let result = Request::from_async_read(&mut reader).await;

        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
        }
    }

    #[tokio::test]
    async fn test_request_from_async_read_incomplete_data() {
        let mut buffer = BytesMut::new();

        // Command only, missing reserved byte
        buffer.put_u8(Request::SOCKS5_CMD_CONNECT);

        let bytes = buffer.freeze();
        let mut cursor = Cursor::new(bytes);
        let mut reader = BufReader::new(&mut cursor);

        let result = Request::from_async_read(&mut reader).await;

        assert!(result.is_err());
    }
}
