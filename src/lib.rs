use std::future::Future;
use std::io::Result;

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[rustfmt::skip]
pub mod consts {
    pub const PORT_LENGTH:          usize = 2;
    pub const IPV4_ADDRESS_LENGTH:  usize = 4;
    pub const IPV6_ADDRESS_LENGTH:  usize = 16;
}

pub trait Streamable {
    fn write<T>(&self, stream: &mut T) -> impl Future<Output = Result<()>> + Send
    where
        Self: ToBytes + Send + Sync,
        T: AsyncWriteExt + Unpin + Send,
    {
        async move { stream.write_all(&self.to_bytes()).await }
    }

    fn read<T>(stream: &mut T) -> impl Future<Output = Result<Self>> + Send
    where
        Self: Sized,
        T: AsyncReadExt + Unpin + Send;
}

pub trait ToBytes {
    fn to_bytes(&self) -> BytesMut;
}