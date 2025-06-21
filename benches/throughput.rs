use std::time::Duration;

use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use tokio::runtime::Runtime;

#[path = "../tests/support.rs"]
mod support;

use support::SocksServer;
use support::curl::*;
use support::mock::*;

const SIZES_KB: &[usize] = &[1, 64, 256, 1024, 10240, 102400];

fn bench_socks5_throughput(c: &mut Criterion) {
    let runtime = Runtime::new().expect("Failed to create Tokio runtime");

    let mut group = c.benchmark_group("SOCKS5 Throughput");
    group.measurement_time(Duration::from_secs(10));

    for &size_kb in SIZES_KB {
        let size_bytes = size_kb * 1024;

        group.throughput(Throughput::Bytes(size_bytes as u64));

        let data_to_transfer = Bytes::from(vec![0u8; size_bytes]);

        group.bench_with_input(
            BenchmarkId::new("No-Auth", format!("{}KB", size_kb)),
            &data_to_transfer,
            |b, data| {
                b.to_async(&runtime).iter_custom(|iters| async move {
                    let http = MockServer::http2_with_data(data.clone()).await;
                    let socks = SocksServer::v5_with_no_auth().await;
                    let http_addr = http.local_addr();
                    let socks_addr = socks.local_addr();

                    let start = std::time::Instant::now();
                    for _ in 0..iters {
                        black_box(curl(
                            &curl_https(http_addr),
                            &curl_proxy_socks5(socks_addr, None),
                        ));
                    }
                    start.elapsed()
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("User-Auth", format!("{}KB", size_kb)),
            &data_to_transfer,
            |b, data| {
                b.to_async(&runtime).iter_custom(|iters| async move {
                    let http = MockServer::http2_with_data(data.clone()).await;
                    let socks = SocksServer::v5_with_user_auth().await;
                    let http_addr = http.local_addr();
                    let socks_addr = socks.local_addr();

                    let start = std::time::Instant::now();
                    for _ in 0..iters {
                        black_box(curl(
                            &curl_https(http_addr),
                            &curl_proxy_socks5(socks_addr, Some(("username", "password"))),
                        ));
                    }
                    start.elapsed()
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_socks5_throughput);
criterion_main!(benches);
