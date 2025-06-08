use std::sync::Arc;
use std::time::Duration;

use socks_lib::io::{self, AsyncRead, AsyncWrite};
use socks_lib::net::{TcpListener, UdpSocket};
use socks_lib::v5::server::auth::NoAuthentication;
use socks_lib::v5::server::{Config, Handler, Server};
use socks_lib::v5::{Address, Request, Response, Stream};

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:1082").await.unwrap();
    println!(
        "SOCKS server listening on {}",
        listener.local_addr().unwrap()
    );

    let config = Config::new(NoAuthentication, CommandHandler);

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
        if let Request::Associate(_addr) = &request {
            let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
            let socket_out = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
            let bind_addr = Address::from(socket.local_addr().unwrap());

            stream
                .write_response(&Response::Success(&bind_addr))
                .await
                .unwrap();

            utils::copy_bidirectional(socket, socket_out, Duration::from_secs(60))
                .await
                .unwrap();
        } else {
            stream.write_response_unsupported().await?;
        }

        Ok(())
    }
}

mod utils {
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::Bytes;
    use socks_lib::v5::{Address, UdpPacket};
    use tokio::io::{Error, ErrorKind, Result};
    use tokio::net::UdpSocket;
    use tokio::time::timeout;

    const DEFAULT_BUF_SIZE: usize = 8 * 1024;

    /// Helper function to parse and forward a UDP packet
    #[inline]
    async fn handle_packet(socket: &Arc<UdpSocket>, buf: &[u8]) -> Result<()> {
        let packet = match UdpPacket::from_bytes(&mut &buf[..]) {
            Ok(p) => p,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("Failed to parse UDP packet: {}", e),
                ));
            }
        };

        socket
            .send_to(&packet.data, packet.address.to_string())
            .await?;

        Ok(())
    }

    pub async fn copy_bidirectional(
        inbound: Arc<UdpSocket>,
        outbound: Arc<UdpSocket>,
        idle_timeout: Duration,
    ) -> Result<()> {
        let mut inbound_buf = [0u8; DEFAULT_BUF_SIZE];
        let mut outbound_buf = [0u8; DEFAULT_BUF_SIZE];

        let inbound_c = inbound.clone();
        let outbound_c = outbound.clone();

        // Wait for the first packet to get the client address and process it
        let (n, client_addr) =
            match timeout(idle_timeout, inbound.recv_from(&mut inbound_buf)).await {
                Ok(Ok((n, addr))) => (n, addr),
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    return Err(Error::new(
                        ErrorKind::TimedOut,
                        "No initial packet received",
                    ));
                }
            };

        // Process the first packet
        handle_packet(&outbound, &inbound_buf[..n]).await?;

        let inbound_handle = tokio::spawn(async move {
            loop {
                match timeout(idle_timeout, inbound_c.recv_from(&mut inbound_buf)).await {
                    Ok(Ok((n, src_addr))) => {
                        // Only accept packets from the first client
                        if src_addr != client_addr {
                            // Clear the buffer and continue
                            inbound_buf = [0u8; DEFAULT_BUF_SIZE];
                            continue;
                        }

                        handle_packet(&outbound_c, &inbound_buf[..n]).await?;
                    }
                    Ok(Err(e)) => return Err(e),
                    Err(_) => break,
                }
            }

            Ok(())
        });

        let outbound_handle = tokio::spawn(async move {
            loop {
                match timeout(idle_timeout, outbound.recv_from(&mut outbound_buf)).await {
                    Ok(Ok((n, src_addr))) => {
                        let data = Bytes::copy_from_slice(&outbound_buf[..n]);
                        let packet = UdpPacket::un_frag(Address::from(src_addr), data);

                        inbound.send_to(&packet.to_bytes(), client_addr).await?;
                    }
                    Ok(Err(e)) => return Err(e),
                    Err(_) => break,
                }
            }

            Ok(())
        });

        tokio::select! {
            result = inbound_handle => result?,
            result = outbound_handle => result?
        }
    }
}
