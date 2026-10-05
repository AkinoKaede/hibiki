use anyhow::{Context, Result, bail};
use axum::body::Body;
use hyper::{Request, client::conn::http1};
use hyper_util::rt::TokioIo;
use std::{net::SocketAddr, time::Duration};
use tokio::{net::TcpStream, time::timeout};
use tokio_util::task::AbortOnDropHandle;

fn target(listen: &str) -> String {
    match listen.parse::<SocketAddr>() {
        Ok(mut address) => {
            if address.ip().is_unspecified() {
                address.set_ip(if address.is_ipv4() {
                    std::net::Ipv4Addr::LOCALHOST.into()
                } else {
                    std::net::Ipv6Addr::LOCALHOST.into()
                });
            }
            address.to_string()
        }
        Err(_) => listen.to_owned(),
    }
}

pub async fn check(listen: &str) -> Result<()> {
    let target = target(listen);
    timeout(Duration::from_secs(2), async {
        let stream = TcpStream::connect(&target).await?;
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream)).await?;
        let _connection = AbortOnDropHandle::new(tokio::spawn(connection));
        let request = Request::builder()
            .uri("/healthz")
            .header(hyper::header::HOST, &target)
            .body(Body::empty())?;
        let status = sender.send_request(request).await?.status();
        if !status.is_success() {
            bail!("health endpoint returned {status}");
        }
        Ok(())
    })
    .await
    .context("health check timed out after 2 seconds")?
    .with_context(|| format!("server health check failed at http://{target}/healthz"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, http::StatusCode, routing::get};

    #[test]
    fn wildcard_addresses_use_matching_loopback() {
        assert_eq!(target("0.0.0.0:7749"), "127.0.0.1:7749");
        assert_eq!(target("[::]:7749"), "[::1]:7749");
        assert_eq!(target("192.0.2.1:9000"), "192.0.2.1:9000");
        assert_eq!(target("localhost:9000"), "localhost:9000");
    }

    #[tokio::test]
    async fn checks_http_status_instead_of_only_tcp_connectivity() {
        for status in [StatusCode::OK, StatusCode::SERVICE_UNAVAILABLE] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let router = Router::new().route("/healthz", get(move || async move { status }));
            let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
            let result = check(&format!("0.0.0.0:{}", address.port())).await;
            assert_eq!(result.is_ok(), status.is_success());
            task.abort();
        }
    }

    #[tokio::test]
    async fn unresponsive_server_times_out() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let error = check(&listener.local_addr().unwrap().to_string())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("timed out"));
    }
}
