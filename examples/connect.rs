use socks_lib::v5::Stream;
use socks_lib::v5::{Address, Method, Request, Response};

use tokio::net::TcpListener;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() {
    let server = TcpListener::bind("127.0.0.1:1080").await.unwrap();

    println!("SOCKS server listening on {}", server.local_addr().unwrap());

    while let Ok((inner, _addr)) = server.accept().await {
        tokio::spawn(async move {
            let mut stream = Stream::with(inner);

            let _methods = stream.read_methods().await.unwrap();
            stream
                .write_auth_method(Method::NoAuthentication)
                .await
                .unwrap();

            let request = stream.read_request().await.unwrap();

            println!("Accpet {:?}", request);

            match &request {
                Request::Connect(addr) => {
                    stream
                        .write_response(&Response::Success(Address::unspecified()))
                        .await
                        .unwrap();

                    let mut target = TcpStream::connect(addr.format_as_string().unwrap())
                        .await
                        .unwrap();

                    let (a_to_b, b_to_a) = utils::copy_bidirectional(&mut stream, &mut target)
                        .await
                        .unwrap();

                    println!("{:?} Send: {}, Receive: {}", request, a_to_b, b_to_a)
                }

                _ => {
                    stream
                        .write_response(&Response::CommandNotSupported)
                        .await
                        .unwrap();
                }
            }
        });
    }
}

mod utils {
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ErrorKind, Result};
    use tokio::sync::broadcast;

    const DEFAULT_BUF_SIZE: usize = 8 * 1024;

    #[inline]
    async fn copy_with_abort<R, W>(
        read: &mut R,
        write: &mut W,
        mut abort: broadcast::Receiver<()>,
    ) -> Result<usize>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        use ErrorKind::{ConnectionAborted, ConnectionReset};

        let mut copied = 0;
        let mut buf = [0u8; DEFAULT_BUF_SIZE];

        loop {
            let bytes_read;

            tokio::select! {
                result = read.read(&mut buf) => {
                    bytes_read = result.or_else(|e| match e.kind() {
                        ConnectionReset | ConnectionAborted => Ok(0),
                        _ => Err(e)
                    })?;
                },
                _ = abort.recv() => {
                    break;
                }
            }

            if bytes_read == 0 {
                break;
            }

            write.write_all(&buf[0..bytes_read]).await?;
            copied += bytes_read;
        }

        Ok(copied)
    }

    pub async fn copy_bidirectional<A, B>(a: &mut A, b: &mut B) -> Result<(u64, u64)>
    where
        A: AsyncRead + AsyncWrite + Unpin + ?Sized,
        B: AsyncRead + AsyncWrite + Unpin + ?Sized,
    {
        let (mut a_reader, mut a_writer) = tokio::io::split(a);
        let (mut b_reader, mut b_writer) = tokio::io::split(b);

        let (cancel, _) = broadcast::channel::<()>(1);

        let (a_to_b_bytes, b_to_a_bytes) = tokio::join! {
            async {
                let result = copy_with_abort(&mut a_reader, &mut b_writer, cancel.subscribe()).await;
                let _ = cancel.send(());
                result
            },
            async {
                let result = copy_with_abort(&mut b_reader, &mut a_writer, cancel.subscribe()).await;
                let _ = cancel.send(());
                result
            }
        };

        Ok((
            a_to_b_bytes.unwrap_or(0) as u64,
            b_to_a_bytes.unwrap_or(0) as u64,
        ))
    }
}
