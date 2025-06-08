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
    #[rustfmt::skip]
    #[inline]
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::NoAuthentication            => 0x00,
            Self::GSSAPI                      => 0x01,
            Self::UsernamePassword            => 0x02,
            Self::IanaAssigned(value)         => *value,
            Self::ReservedPrivate(value)      => *value,
            Self::NoAcceptableMethod          => 0xFF,
        }
    }

    #[rustfmt::skip]
    #[inline]
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
