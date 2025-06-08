use std::net::SocketAddr;

use bytes::BytesMut;

use crate::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use crate::v5::{Request, Response, method::Method};

pub struct Stream<T>(T, SocketAddr);

impl<T> Stream<T> {
    #[inline]
    pub fn version(&self) -> u8 {
        0x05
    }

    #[inline]
    pub fn peer_addr(&self) -> SocketAddr {
        self.1
    }

    #[inline]
    pub fn with(inner: T, addr: SocketAddr) -> Self {
        Self(inner, addr)
    }
}

// ===== STREAM Server Side Impl =====
impl<T> Stream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// # Methods
    ///
    /// ```text
    ///  +----+----------+----------+
    ///  |VER | NMETHODS | METHODS  |
    ///  +----+----------+----------+
    ///  | 1  |    1     | 1 to 255 |
    ///  +----+----------+----------+
    /// ```
    #[inline]
    pub async fn read_methods(&mut self) -> io::Result<Vec<Method>> {
        let mut buffer = [0u8; 2];
        self.0.read_exact(&mut buffer).await?;

        let method_num = buffer[1];
        if method_num == 1 {
            let method = self.0.read_u8().await?;
            return Ok(vec![Method::from_u8(method)]);
        }

        let mut methods = vec![0u8; method_num as usize];
        self.0.read_exact(&mut methods).await?;

        let result = methods.into_iter().map(Method::from_u8).collect();

        Ok(result)
    }

    ///
    /// ```text
    ///  +----+--------+
    ///  |VER | METHOD |
    ///  +----+--------+
    ///  | 1  |   1    |
    ///  +----+--------+
    ///  ```
    #[inline]
    pub async fn write_auth_method(&mut self, method: Method) -> io::Result<usize> {
        let bytes = [self.version(), method.as_u8()];
        self.0.write(&bytes).await
    }

    ///
    /// ```text
    ///  +----+-----+-------+------+----------+----------+
    ///  |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    ///  +----+-----+-------+------+----------+----------+
    ///  | 1  |  1  | X'00' |  1   | Variable |    2     |
    ///  +----+-----+-------+------+----------+----------+
    /// ```
    ///
    #[inline]
    pub async fn read_request(&mut self) -> io::Result<Request> {
        let _version = self.0.read_u8().await?;
        Request::from_async_read(&mut self.0).await
    }

    ///
    /// ```text
    ///  +----+-----+-------+------+----------+----------+
    ///  |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    ///  +----+-----+-------+------+----------+----------+
    ///  | 1  |  1  | X'00' |  1   | Variable |    2     |
    ///  +----+-----+-------+------+----------+----------+
    /// ```
    ///
    #[inline]
    pub async fn write_response<'a>(&mut self, resp: &Response<'a>) -> io::Result<usize> {
        let bytes = prepend_u8(resp.to_bytes(), self.version());
        self.0.write(&bytes).await
    }

    #[inline]
    pub async fn write_response_unspecified(&mut self) -> io::Result<usize> {
        use crate::v5::Address;
        self.write_response(&Response::Success(Address::unspecified()))
            .await
    }

    #[inline]
    pub async fn write_response_unsupported(&mut self) -> io::Result<usize> {
        self.write_response(&Response::CommandNotSupported).await
    }
}

#[inline]
fn prepend_u8(mut bytes: BytesMut, value: u8) -> BytesMut {
    bytes.reserve(1);

    unsafe {
        let ptr = bytes.as_mut_ptr();
        std::ptr::copy(ptr, ptr.add(1), bytes.len());
        std::ptr::write(ptr, value);
        let new_len = bytes.len() + 1;
        bytes.set_len(new_len);
    }

    bytes
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
            AsyncRead::poll_read(Pin::new(&mut self.0), cx, buf)
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
            AsyncWrite::poll_write(Pin::new(&mut self.0), cx, buf)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            AsyncWrite::poll_flush(Pin::new(&mut self.0), cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            AsyncWrite::poll_shutdown(Pin::new(&mut self.0), cx)
        }
    }
}
