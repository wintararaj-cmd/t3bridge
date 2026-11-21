mod admin_http;
mod handler;
mod registry;

use registry::PeerRegistry;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let port = env::var("PORT").unwrap_or_else(|_| "8088".to_string());
    let bind_addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;

    println!("========================================================");
    println!("       t3Bridge - Cloud Signaling Rendezvous Server     ");
    println!("========================================================");
    println!("[*] Listening on: ws://{}", bind_addr);

    let listener = TcpListener::bind(&bind_addr).await?;
    let registry = Arc::new(PeerRegistry::new());

    while let Ok((stream, addr)) = listener.accept().await {
        let reg = Arc::clone(&registry);
        tokio::spawn(async move {
            handler::handle_connection(stream, addr, reg).await;
        });
    }

    Ok(())
}
