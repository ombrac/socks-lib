use socks_lib::io::{self, AsyncRead, AsyncWrite};
use socks_lib::net::{TcpListener, TcpStream};
use socks_lib::v5::server::auth::UserPassword;
use socks_lib::v5::server::{Config, Handler, Server};
use socks_lib::v5::{Request, Stream};

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:1081").await.unwrap();
    println!(
        "SOCKS server listening on {}",
        listener.local_addr().unwrap()
    );

    let config = Config::new(
        UserPassword::new("username".into(), "password".into()),
        CommandHandler,
    );

    Server::run(listener, config.into(), async {
        tokio::signal::ctrl_c().await.unwrap();
    })
    .await
    .unwrap();
}

pub struct CommandHandler;

impl Handler for CommandHandler {
    async fn handle<T>(&self, stream: &mut Stream<T>, request: Request) -> io::Result<()>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + Sync,
    {
        if let Request::Connect(addr) = &request {
            stream.write_response_unspecified().await?;

            let mut target = TcpStream::connect(addr.to_string()).await?;
            let copy = utils::copy_bidirectional(stream, &mut target).await?;

            println!(
                "{} {:?} Send: {}, Receive: {}",
                stream.peer_addr(),
                request,
                copy.0,
                copy.1
            );
        } else {
            stream.write_response_unsupported().await?;
        }

        Ok(())
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
