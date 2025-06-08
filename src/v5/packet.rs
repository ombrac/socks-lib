use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::io;
use crate::v5::Address;

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
    pub fn from_bytes<B: Buf>(buf: &mut B) -> io::Result<Self> {
        if buf.remaining() < 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Insufficient data for RSV",
            ));
        }
        buf.advance(2);

        if buf.remaining() < 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Insufficient data for FRAG",
            ));
        }
        let frag = buf.get_u8();

        let address = Address::from_bytes(buf)?;

        let data = buf.copy_to_bytes(buf.remaining());

        Ok(Self {
            frag,
            address,
            data,
        })
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
