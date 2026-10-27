//! `voidwire-push-gw`: stateless blind push forwarder (plan §2, §3 "sealed token").
//!
//! **M0 stub.** Only `/healthz` works. `/v1/seal` and `/v1/push` answer
//! 501 Not Implemented until M3 (APNs/FCM). No logging of request bodies,
//! tokens or IPs, ever.

use axum::{http::StatusCode, routing::get, routing::post, Router};
use std::net::SocketAddr;

pub fn app() -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/v1/seal",
            post(|| async { (StatusCode::NOT_IMPLEMENTED, "not implemented (M3)") }),
        )
        .route(
            "/v1/push",
            post(|| async { (StatusCode::NOT_IMPLEMENTED, "not implemented (M3)") }),
        )
}

/// `<ENV_PREFIX>_PUSH_GW_ADDR`, prefix from branding.properties (D9).
fn addr_env_var() -> String {
    format!("{}_PUSH_GW_ADDR", env!("VOIDWIRE_BRAND_ENV_PREFIX"))
}

#[tokio::main]
async fn main() {
    let addr: SocketAddr = std::env::var(addr_env_var())
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 8787)));
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    eprintln!("push-gw (stub) listening on http://{addr}");
    axum::serve(listener, app())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .expect("server");
}

#[cfg(test)]
mod tests {
    use super::app;

    #[test]
    fn env_var_prefix_comes_from_branding() {
        let props = include_str!("../../branding.properties");
        let prefix = props
            .lines()
            .find_map(|l| l.trim().strip_prefix("ENV_PREFIX="))
            .unwrap()
            .trim();
        assert_eq!(super::addr_env_var(), format!("{prefix}_PUSH_GW_ADDR"));
    }
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn healthz_ok_and_push_not_implemented() {
        let r = app()
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let r = app()
            .oneshot(Request::post("/v1/push").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::NOT_IMPLEMENTED);
    }
}
