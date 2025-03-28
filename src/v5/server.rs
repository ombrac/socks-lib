use std::io;

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{Method, Request, Response, Stream};

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

        let result = methods.into_iter().map(|e| Method::from_u8(e)).collect();

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
        let bytes = [self.version().into(), method.as_u8()];
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
        let bytes = prepend_u8(resp.to_bytes(), self.version().into());
        self.0.write(&bytes).await
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
