use std::io;
use std::net::SocketAddr;

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, ToSocketAddrs};

use super::{Method, Request, Response, Stream};

pub struct Server {
    listener: TcpListener,
}

impl Server {
    const VERSION_5: u8 = 0x05;

    pub async fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(addr).await?,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    #[inline]
    pub async fn accept(
        &self,
    ) -> io::Result<(
        Request,
        Stream<impl AsyncRead + AsyncWrite + Unpin + 'static>,
    )> {
        let (inner, from) = self.listener.accept().await?;
        let inner = BufReader::new(inner);
        let mut stream = Stream::with(Self::VERSION_5, from, inner);

        let _methods = stream.read_methods().await?;

        // TODO: impl username password
        stream.write_auth_method(Method::NoAuthentication).await?;

        let request = stream.read_request().await?;

        Ok((request, stream))
    }
}

impl<T> Stream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn with<A: Into<SocketAddr>>(version: u8, from: A, inner: BufReader<T>) -> Self {
        Self {
            version,
            from: from.into(),
            inner,
        }
    }

    /// # Methods
    ///
    /// ```
    ///  +----+----------+----------+
    ///  |VER | NMETHODS | METHODS  |
    ///  +----+----------+----------+
    ///  | 1  |    1     | 1 to 255 |
    ///  +----+----------+----------+
    /// ```
    #[inline]
    async fn read_methods(&mut self) -> io::Result<Vec<Method>> {
        let mut buffer = [0u8; 2];
        self.inner.read_exact(&mut buffer).await?;

        let method_num = buffer[1];
        if method_num == 1 {
            let method = self.inner.read_u8().await?;
            return Ok(vec![Method::from_u8(method)]);
        }

        let mut methods = vec![0u8; method_num as usize];
        self.inner.read_exact(&mut methods).await?;

        let result = methods.into_iter().map(|e| Method::from_u8(e)).collect();

        Ok(result)
    }

    ///
    /// ```
    ///  +----+--------+
    ///  |VER | METHOD |
    ///  +----+--------+
    ///  | 1  |   1    |
    ///  +----+--------+
    ///  ```
    #[inline]
    async fn write_auth_method(&mut self, method: Method) -> io::Result<usize> {
        let bytes = [self.version, method.as_u8()];
        self.inner.write(&bytes).await
    }

    ///
    /// ```
    ///  +----+-----+-------+------+----------+----------+
    ///  |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    ///  +----+-----+-------+------+----------+----------+
    ///  | 1  |  1  | X'00' |  1   | Variable |    2     |
    ///  +----+-----+-------+------+----------+----------+
    /// ```
    ///
    #[inline]
    async fn read_request(&mut self) -> io::Result<Request> {
        let _version = self.inner.read_u8().await?;
        Request::from_async_read(&mut self.inner).await
    }

    ///
    /// ```
    ///  +----+-----+-------+------+----------+----------+
    ///  |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    ///  +----+-----+-------+------+----------+----------+
    ///  | 1  |  1  | X'00' |  1   | Variable |    2     |
    ///  +----+-----+-------+------+----------+----------+
    /// ```
    ///
    #[inline]
    pub async fn write_response<'a>(&mut self, resp: &Response<'a>) -> io::Result<usize> {
        let bytes = prepend_u8(resp.to_bytes(), self.version);
        self.inner.write(&bytes).await
    }
}

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
