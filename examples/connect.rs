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
            let copy = io::copy_bidirectional(stream, &mut target).await?;

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
