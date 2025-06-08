use std::net::SocketAddr;

use socks_lib::v5::server::auth::{NoAuthentication, UserPassword};
use socks_lib::v5::server::{Config, Handler, Server};
use socks_lib::v5::{Request, Stream};
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

pub struct SocksServer(SocketAddr, JoinHandle<()>);

impl SocksServer {
    pub fn local_addr(&self) -> SocketAddr {
        self.0
    }

    pub async fn v5_with_no_auth() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let config = Config::new(NoAuthentication, ConnectHandler);

        let task = tokio::spawn(async move {
            Server::run(listener, config.into(), async {
                tokio::signal::ctrl_c().await.unwrap();
            })
            .await
            .unwrap();
        });

        Self(address, task)
    }

    pub async fn v5_with_user_auth() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let config = Config::new(
            UserPassword::new("username".into(), "password".into()),
            ConnectHandler,
        );

        let task = tokio::spawn(async move {
            Server::run(listener, config.into(), async {
                tokio::signal::ctrl_c().await.unwrap();
            })
            .await
            .unwrap();
        });

        Self(address, task)
    }
}

impl Drop for SocksServer {
    fn drop(&mut self) {
        self.1.abort();
    }
}

pub struct ConnectHandler;

impl Handler for ConnectHandler {
    async fn handle<T>(&self, stream: &mut Stream<T>, request: Request) -> io::Result<()>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + Sync,
    {
        if let Request::Connect(addr) = &request {
            stream.write_response_unspecified().await?;

            let mut target = TcpStream::connect(addr.to_string()).await?;
            io::copy_bidirectional(stream, &mut target).await?;
        } else {
            stream.write_response_unsupported().await?;
        }

        Ok(())
    }
}

pub mod curl {
    use std::{net::SocketAddr, time::Duration};

    pub fn curl(url: &str, proxy: &str) -> (u32, Vec<u8>) {
        let mut handle = curl::easy::Easy::new();

        handle.get(true).unwrap();
        handle.url(url).unwrap();
        handle.proxy(proxy).unwrap();
        handle.ssl_verify_peer(false).unwrap();
        handle.ssl_verify_host(false).unwrap();
        handle.timeout(Duration::from_secs(3)).unwrap();

        handle.perform().unwrap();

        let mut response = Vec::new();
        {
            let mut transfer = handle.transfer();
            transfer
                .write_function(|data| {
                    response.extend_from_slice(data);
                    Ok(data.len())
                })
                .unwrap();

            transfer.perform().unwrap();
        }

        (handle.response_code().unwrap(), response)
    }

    pub fn curl_https(addr: SocketAddr) -> String {
        format!("https://{addr}")
    }

    pub fn curl_proxy_socks5(addr: SocketAddr, user: Option<(&str, &str)>) -> String {
        match user {
            Some((name, pass)) => format!("socks5://{name}:{pass}@{addr}"),
            None => format!("socks5://{addr}"),
        }
    }

    pub fn curl_proxy_socks5h(addr: SocketAddr, user: Option<(&str, &str)>) -> String {
        match user {
            Some((name, pass)) => format!("socks5h://{name}:{pass}@{addr}"),
            None => format!("socks5h://{addr}"),
        }
    }
}

pub mod mock {
    use std::convert::Infallible;
    use std::net::SocketAddr;
    use std::sync::Arc;

    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::server::conn::http2;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls::{self, ServerConfig};

    pub struct MockServer(SocketAddr, JoinHandle<()>);

    impl MockServer {
        pub fn local_addr(&self) -> SocketAddr {
            self.0
        }

        pub async fn http2_hello() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();

            let tls_config = load_rustls_config();
            let tls_acceptor = TlsAcceptor::from(tls_config);

            let task = tokio::spawn(async move {
                loop {
                    let (stream, _peer_addr) = listener.accept().await.unwrap();
                    let tls_acceptor = tls_acceptor.clone();

                    tokio::spawn(async move {
                        let stream = tls_acceptor.accept(stream).await.unwrap();
                        let io = TokioIo::new(stream);

                        http2::Builder::new(TokioExecutor::new())
                            .serve_connection(io, service_fn(hello))
                            .await
                            .unwrap();
                    });
                }
            });

            Self(address, task)
        }
    }

    pub const HELLO_WORLD: &[u8; 13] = b"Hello, World!";

    async fn hello(_: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
        Ok(Response::new(Full::new(Bytes::from_static(HELLO_WORLD))))
    }

    fn load_rustls_config() -> Arc<ServerConfig> {
        let signed = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certs = vec![CertificateDer::from(signed.cert)];
        let key = PrivatePkcs8KeyDer::from(signed.key_pair.serialize_der()).into();

        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("bad certificate or key");

        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Arc::new(config)
    }

    impl Drop for MockServer {
        fn drop(&mut self) {
            self.1.abort();
        }
    }
}
