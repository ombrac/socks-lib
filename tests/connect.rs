use crate::support::SocksServer;
use crate::support::curl::*;
use crate::support::mock::*;

#[path = "./support.rs"]
mod support;

#[tokio::test(flavor = "multi_thread")]
async fn test_socks() {
    let http = MockServer::http2_hello().await;
    let socks = SocksServer::v5_with_no_auth().await;

    let resp = curl(
        &curl_https(http.local_addr()),
        &curl_proxy_socks5(socks.local_addr(), None),
    );
    assert_eq!(resp.0, 200);
    assert_eq!(resp.1, HELLO_WORLD);

    let resp = curl(
        &curl_https(http.local_addr()),
        &curl_proxy_socks5h(socks.local_addr(), None),
    );
    assert_eq!(resp.0, 200);
    assert_eq!(resp.1, HELLO_WORLD);
}

#[tokio::test(flavor = "multi_thread")]
async fn start_server2() {
    let http = MockServer::http2_hello().await;
    let socks = SocksServer::v5_with_user_auth().await;

    let resp = curl(
        &curl_https(http.local_addr()),
        &curl_proxy_socks5(socks.local_addr(), Some(("username", "password"))),
    );
    assert_eq!(resp.0, 200);
    assert_eq!(resp.1, HELLO_WORLD);

    let resp = curl(
        &curl_https(http.local_addr()),
        &curl_proxy_socks5(socks.local_addr(), Some(("username", "password"))),
    );
    assert_eq!(resp.0, 200);
    assert_eq!(resp.1, HELLO_WORLD);
}
