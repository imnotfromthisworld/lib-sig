use lib_sig::message::EncryptedMessage;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_stream::StreamExt;
use tokio_util::codec::{Framed, LinesCodec};

use futures::SinkExt;
use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::metadata::LevelFilter;
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with_span_events(FmtSpan::FULL)
        .init();

    let state = Arc::new(Mutex::new(Shared::new()));

    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:6142".to_string());

    let listener = TcpListener::bind(&addr).await?;

    tracing::info!("server running on {}", addr);

    loop {
        let (stream, addr) = listener.accept().await?;

        let state = Arc::clone(&state);

        tokio::spawn(async move {
            tracing::info!("accepted connection on address: {}", addr);
            if let Err(e) = process(state, stream, addr).await {
                tracing::info!("an error occurred; error = {:?}", e);
            }
        });
    }
}

type Tx = mpsc::UnboundedSender<String>;
type Rx = mpsc::UnboundedReceiver<String>;

struct Shared {
    peers: HashMap<SocketAddr, Tx>,
    peer_names: HashMap<String, SocketAddr>,
}

struct Peer {
    lines: Framed<TcpStream, LinesCodec>,
    rx: Rx,
}

impl Shared {
    fn new() -> Self {
        Shared {
            peers: HashMap::new(),
            peer_names: HashMap::new(),
        }
    }
}

impl Peer {
    async fn new(
        state: Arc<Mutex<Shared>>,
        lines: Framed<TcpStream, LinesCodec>,
        username: &String,
    ) -> io::Result<Peer> {
        let addr = lines.get_ref().peer_addr()?;

        let (tx, rx) = mpsc::unbounded_channel();

        state.lock().await.peers.insert(addr, tx);
        state
            .lock()
            .await
            .peer_names
            .insert(username.to_owned(), addr);

        Ok(Peer { lines, rx })
    }
}

async fn process(
    state: Arc<Mutex<Shared>>,
    stream: TcpStream,
    addr: SocketAddr,
) -> Result<(), Box<dyn Error>> {
    let mut lines = Framed::new(stream, LinesCodec::new());

    // try to get username
    let username = match lines.next().await {
        Some(Ok(line)) => line,
        _ => {
            tracing::error!("Client {} did not send a username.", addr);
            return Ok(());
        }
    };

    let mut peer = Peer::new(state.clone(), lines, &username).await?;
    tracing::info!("{} has connected to the server", &username);

    loop {
        tokio::select! {
        Some(msg) = peer.rx.recv() => {
            peer.lines.send(&msg).await?;
        }
        result = peer.lines.next() => match result {
            Some(Ok(msg)) => {
                let message: EncryptedMessage = serde_json::from_str(&msg).unwrap();
                let state = state.lock().await;

                if let Some(value) = state.peer_names.get(&message.recv_name) {
                    let x = state.peers.get(value).unwrap();
                    if let Err(e) = x.send(msg) {
                        tracing::info!("Username `{}` has no matching socket, {}", message.recv_name, e);
                    }
                } else {
                    tracing::info!("Tried to send message to nonexisting user {}", message.recv_name);
                }
            }
            Some(Err(e)) => {
                tracing::error!("Failed to read messages: {:?}", e);
            }
            None => break,
            },
        }
    }

    let mut state = state.lock().await;
    state.peers.remove(&addr);
    state.peer_names.remove(&username);
    tracing::info!("{} has disconnected from the server", username);

    Ok(())
}
