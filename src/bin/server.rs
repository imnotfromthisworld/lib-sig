use lib_sig::message::{ErrMessage, Info, Msg, PubKey};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_stream::StreamExt;
use tokio_util::codec::{Framed, LinesCodec};

use futures::SinkExt;
use std::env;
use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::metadata::LevelFilter;
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};
use x25519_dalek::PublicKey;

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

struct Data {
    addr: SocketAddr,
    name: String,
    tx: Tx,
    pub_key: Option<PublicKey>,
}

impl Data {
    fn set_key(&mut self, key: PublicKey) {
        self.pub_key = Some(key);
    }
}

struct Shared {
    peers: Vec<Data>,
}

struct Peer {
    lines: Framed<TcpStream, LinesCodec>,
    rx: Rx,
}

impl Shared {
    fn new() -> Self {
        Shared { peers: Vec::new() }
    }
    async fn send(&mut self, peer_name: &String, msg: &str) -> Result<(), String> {
        match self.get_name(peer_name) {
            Some(x) => {
                if let Err(e) = x.tx.send(msg.to_string()) {
                    tracing::info!("failed to send message to {}, msg: {}", peer_name, e);
                }
                Ok(())
            }
            None => {
                tracing::info!("user {} does not exist", peer_name);
                Err("user does not exist".to_string())
            }
        }
    }
    fn get_name(&self, peer_name: &String) -> Option<&Data> {
        self.peers.iter().find(|&x| x.name == *peer_name)
    }

    fn set_key(&mut self, peer_name: &String, key: PublicKey) {
        for x in self.peers.iter_mut() {
            if x.name == *peer_name {
                x.set_key(key);
                break;
            }
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

        for x in state.lock().await.peers.iter() {
            let k = Msg::PubKey(PubKey::new(x.name.clone(), x.pub_key.unwrap()));
            if let Err(e) = tx.send(serde_json::to_string(&k).unwrap()) {
                tracing::error!("failed to send message to {}, msg: {}", username, e);
            }
        }

        state.lock().await.peers.push(Data {
            addr,
            name: username.to_owned(),
            tx,
            pub_key: None,
        });

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
        Some(Ok(line)) => {
            let msg: Msg = serde_json::from_str(&line).unwrap();

            match msg {
                Msg::Register(msg) => {
                    if let Some(peer) = state.lock().await.get_name(&msg.client_name) {
                        let ret = Msg::Err(ErrMessage::new("user already exists".to_owned()));

                        if let Err(e) = peer.tx.send(serde_json::to_string(&ret).unwrap()) {
                            tracing::error!(
                                "failed to send message to {}, msg: {}",
                                msg.client_name,
                                e
                            );
                            return Ok(());
                        }
                    }
                    msg.client_name
                }
                _ => {
                    tracing::error!(
                        "client {} did not send a register message. msg: {}",
                        addr,
                        line
                    );
                    return Ok(());
                }
            }
        }
        _ => {
            tracing::error!("failed to parse register message. client: {}", addr);
            return Ok(());
        }
    };

    let mut peer = Peer::new(state.clone(), lines, &username).await?;
    tracing::info!("{} has connected to the server", &username);

    {
        let mut motd = String::from("Welcome to this simple server! Users currently connected: ");
        let mut st = state.lock().await;

        motd.push_str(
            &st.peers
                .iter()
                .map(|x| x.name.clone())
                .collect::<Vec<_>>()
                .join(", "),
        );

        let msg = serde_json::to_string(&Msg::Info(Info::new(motd))).unwrap();
        tracing::debug!("sending motd: {}", &msg);

        let _ = st.send(&username, &msg).await;
    }

    loop {
        tokio::select! {
        Some(msg) = peer.rx.recv() => {
            peer.lines.send(&msg).await?;
        }
        result = peer.lines.next() => match result {
            Some(Ok(message)) => {
                let msg: Msg = serde_json::from_str(&message).unwrap();
                let state = &mut state.lock().await;
                match msg {
                    Msg::EncryptedMessage(msg) => {
                        if let Some(peer) = state.get_name(&msg.recv_name) {
                            if let Err(e) = peer.tx.send(message) {
                                tracing::error!("username `{}` has no matching socket, {}", msg.recv_name, e);
                            }
                        } else {
                            tracing::error!("tried to send message to nonexisting user {}", msg.recv_name);
                        }
                    },
                    Msg::PubKey(msg) => {
                        if let Some(p) =  state.get_name(&username) {
                            if p.pub_key.is_none() {
                                state.set_key(&username, msg.public_key);
                            }

                            for x in state.peers.iter() {
                                if x.name != username {
                                    let k =
                                        Msg::PubKey(PubKey::new(username.clone(), msg.public_key));
                                        if let Err(e) = x.tx.send(serde_json::to_string(&k).unwrap()) {
                                            tracing::error!(
                                                "failed to send message to {}, msg: {}",
                                                x.name,
                                                e
                                            );
                                        }
                                }
                            }

                        }
                    },
                    _ => (),
                }
            }
            Some(Err(e)) => {
                tracing::error!("failed to read messages: {:?}", e);
            }
            None => break,
            },
        }
    }

    let mut state = state.lock().await;
    for (i, x) in state.peers.iter().enumerate() {
        if x.addr == addr {
            state.peers.remove(i);
            break;
        }
    }

    tracing::info!("{} has disconnected from the server", username);
    Ok(())
}
