use std::future::Future;
use std::io::Result;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use socks_lib::socks5::{Address, Method, Request, Response, UdpPacket};
use socks_lib::{Streamable, ToBytes};

struct Socks5Server();

impl Server for Socks5Server {}

impl Authentication for Socks5Server {
    async fn select(&self, _methods: Vec<Method>) -> Result<Method> {
        Ok(Method::NoAuthentication)
    }

    async fn process<T>(&self, _stream: &mut T) -> Result<()>
    where
        T: AsyncReadExt + AsyncWriteExt + Unpin + Send,
    {
        Ok(())
    }
}

impl Evaluator for Socks5Server {
    async fn evaluate<S>(&self, stream: Arc<Mutex<S>>, request: Request) -> Result<Response>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
    {
        use tokio::io::copy_bidirectional;
        use tokio::net::TcpStream;

        println!("{:?}", request);
        let response = match request {
            Request::Connect(target) => {
                let addr = to_socket_address(target).await?;
                let mut connect = TcpStream::connect(addr).await?;

                tokio::spawn(async move {
                    let mut stream_lock = stream.lock().await;
                    copy_bidirectional(&mut (*stream_lock), &mut connect)
                        .await
                        .expect("copy bidirectional error");
                });

                Response::unspecified_success()
            }

            Request::Associate(target) => {
                let addr = to_socket_address(target).await?;

                // IPV4 & IPV6
                let socket_addr = match addr {
                    SocketAddr::V4(_) => "0.0.0.0:0",
                    SocketAddr::V6(_) => "[::]:0",
                };

                let inbound = UdpSocket::bind(socket_addr).await?;
                let outbound = UdpSocket::bind(socket_addr).await?;

                let address = Address::from_socket_address(inbound.local_addr()?);

                tokio::spawn(async move {
                    let mut stream_lock = stream.lock().await;
                    tokio::select! {
                        // TCP Stream closed
                        _ = stream_lock.read_u8() => {}

                        // UDP Transfer
                        _ = transfer_udp(inbound, outbound) => {}
                    }
                });

                Response::Success(address)
            }
            Request::Bind(_) => todo!(),
        };

        Ok(response)
    }
}

async fn handle_udp_response(inbound: &UdpSocket, outbound: &UdpSocket) -> Result<()> {
    let mut buffer = vec![0u8; 8192];

    loop {
        let (size, remote_addr) = outbound.recv_from(&mut buffer).await?;

        let data = (&buffer[..size]).into();
        let address = Address::from_socket_address(remote_addr);
        let packet = UdpPacket::un_frag(address, data);

        inbound.send(&packet.to_bytes()).await?;
    }
}

async fn handle_udp_request(inbound: &UdpSocket, outbound: &UdpSocket) -> Result<()> {
    let mut buffer = vec![0u8; 8192];

    loop {
        let (size, client_addr) = inbound.recv_from(&mut buffer).await?;

        inbound.connect(client_addr).await?;

        let packet = UdpPacket::read(&mut &buffer[..size]).await?;
        let address = to_socket_address(packet.address).await?;

        outbound.send_to(&packet.data, address).await?;
    }
}

async fn transfer_udp(inbound: UdpSocket, outbound: UdpSocket) -> Result<()> {
    use tokio::try_join;

    match try_join!(
        handle_udp_request(&inbound, &outbound),
        handle_udp_response(&inbound, &outbound)
    ) {
        Ok(_) => {}
        Err(error) => return Err(error),
    }

    Ok(())
}

pub trait Authentication {
    fn select(&self, methods: Vec<Method>) -> impl Future<Output = Result<Method>> + Send;
    fn process<S>(&self, stream: &mut S) -> impl Future<Output = Result<()>> + Send
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin + Send;
}

pub trait Evaluator {
    fn evaluate<S>(
        &self,
        stream: Arc<Mutex<S>>,
        request: Request,
    ) -> impl Future<Output = Result<Response>> + Send
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static;
}

pub trait Server
where
    Self: Authentication + Evaluator,
    Self: Sized + Send + Sync + 'static,
{
    fn start(self, address: impl Into<SocketAddr>) -> impl Future<Output = Result<()>> + Send {
        let inner = Arc::new(self);
        let address = address.into();

        async move {
            use tokio::net::TcpListener;

            let listener = TcpListener::bind(address).await?;

            while let Ok((stream, _address)) = listener.accept().await {
                let inner = inner.clone();
                tokio::spawn(async move {
                    inner.handle(stream).await.unwrap();
                });
            }

            Ok(())
        }
    }

    fn handle<S>(&self, mut stream: S) -> impl Future<Output = Result<()>> + Send
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
    {
        async move {
            // Read Authentication
            let methods = Self::read_from(&mut stream).await?;

            // Authentication
            let method = Authentication::select(self, methods).await?;
            Self::write_to(&mut stream, &method).await?;

            // Process Authentication
            if !matches!(method, Method::NoAuthentication) {
                Authentication::process(self, &mut stream).await?;
            }

            // Read Request
            let request = Self::read_from(&mut stream).await?;

            // Evaluate Request
            let stream = Arc::new(Mutex::new(stream));

            {
                let mut stream_lock = stream.lock().await;
                let response = Evaluator::evaluate(self, stream.clone(), request).await?;
                Self::write_to(&mut (*stream_lock), &response).await?;
            }

            Ok(())
        }
    }

    fn write_to<S, T>(stream: &mut S, message: &T) -> impl Future<Output = Result<()>> + Send
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin + Send,
        T: Streamable + ToBytes + Send + Sync,
    {
        async { T::write(message, stream).await }
    }

    fn read_from<S, T>(stream: &mut S) -> impl Future<Output = Result<T>> + Send
    where
        T: Streamable,
        S: AsyncReadExt + AsyncWriteExt + Unpin + Send,
    {
        async { T::read(stream).await }
    }
}

pub async fn to_socket_address(address: Address) -> Result<SocketAddr> {
    use std::io::Error;
    use tokio::net::lookup_host;

    match address {
        Address::IPv4(value) => Ok(value.into()),
        Address::IPv6(value) => Ok(value.into()),
        Address::Domain(domain, port) => lookup_host((domain.as_str(), port))
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| Error::other(format!("could not resolve domain '{}'", domain))),
    }
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let address = "127.0.0.1:1081";
            println!("SOCKS5 Server Listening {}", address);

            Socks5Server()
                .start(address.parse::<SocketAddr>().unwrap())
                .await
                .unwrap();
        });

    Ok(())
}