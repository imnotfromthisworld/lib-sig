use lib_sig::crypto::KeyPair;
use lib_sig::message::PubKey;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_util::codec::{Framed, LinesCodec};

use futures::SinkExt;
use rand::distributions::{Alphanumeric, DistString};
use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::io;
use std::thread;
use tracing::metadata::LevelFilter;
use x25519_dalek::PublicKey;

use lib_sig::crypto::State;
use lib_sig::message::{Message, Msg, RegisterMessage};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with_span_events(FmtSpan::FULL)
        .init();

    // generates random 8 char string if no username supplied
    let username = env::args()
        .nth(1)
        .unwrap_or_else(|| Alphanumeric.sample_string(&mut rand::thread_rng(), 8));

    let reg = Msg::Register(RegisterMessage::new(username.clone()));

    let addr = env::args()
        .nth(2)
        .unwrap_or_else(|| "127.0.0.1:6142".to_string());

    let stream = TcpStream::connect(addr).await?;
    let my_key = KeyPair::new();

    let (tx, mut rx) = mpsc::unbounded_channel();

    // separate thread for getting input from stdio
    // sends it through channel to main thread that asynchronously processes it,
    // encrypts it and serialized sends it to server
    thread::spawn(move || loop {
        let mut buf = String::new();
        io::stdin().read_line(&mut buf).unwrap();
        tx.send(buf).unwrap();
    });

    let mut keys: HashMap<String, PublicKey> = HashMap::new();
    let mut states: HashMap<String, State> = HashMap::new();

    let mut lines = Framed::new(stream, LinesCodec::new());

    lines.send(serde_json::to_string(&reg).unwrap()).await?;

    // send our public key to server
    let pubkey = Msg::PubKey(PubKey::new(username.clone(), my_key.public()));
    lines.send(serde_json::to_string(&pubkey).unwrap()).await?;

    loop {
        tokio::select! {
        Some(msg) = rx.recv() => {
            if msg.starts_with('!') {
                if msg.starts_with("!help") {
                    tracing::info!("to message someone type: username>message");
                }
                else if msg.starts_with("!list") {
                    tracing::info!("connected users: {}, {}", states.keys().cloned().collect::<Vec<_>>().join(", "), &username);
                }
            }
            else {
                let mut spl = msg.split('>');
                if let Some(peer) = spl.next() {
                    if peer == username {
                        tracing::info!("cannot message yourself");
                        continue;
                    }
                    if !keys.contains_key(peer) {
                        tracing::info!("the user you tried to message does not exist: {}", peer);
                        continue;
                    }

                    let msg = spl.next().unwrap_or("");
                    if !states.contains_key(peer) {
                        states.insert(peer.to_string(), State::new(my_key.clone(), *keys.get(peer).unwrap()));
                    }

                    let st = states.get_mut(peer).unwrap();
                    let msg = Message::new(msg.to_owned(), username.clone(), peer.to_string(),
                        st.key_pair().public());
                    let (msg, new_state) = msg.encrypt(st).unwrap();
                    *st = new_state;

                    let msg = serde_json::to_string(&Msg::EncryptedMessage(msg)).unwrap();
                    tracing::debug!("sending message to server: {}", msg);
                    lines.send(&msg).await?;
                }
                else {
                    tracing::info!("wrong message format, to write message use \"<user> > <msg>\"");
                    continue;
                }
            }
        }

        result = lines.next() => match result {
            Some(Ok(message)) => {
                tracing::debug!("received message: {}", message);
                let msg: Msg = serde_json::from_str(&message).unwrap();
                match msg {
                    Msg::EncryptedMessage(msg) => {
                        let st = states.get_mut(&msg.sender_name).unwrap();
                        let (msg, new_state) = msg.decrypt(st).unwrap();

                        *st = new_state;
                        tracing::info!("{}: {}", msg.sender_name, msg.msg.trim());
                    }
                    Msg::PubKey(msg) => {
                        if msg.user != username {
                            keys.insert(msg.user.clone(), msg.public_key);
                            if  states.get(&msg.user).is_none() {
                                states.insert(msg.user.clone(), State::new(my_key.clone(), msg.public_key));
                            }
                        }
                    }
                    Msg::Info(msg) => {
                        tracing::info!("{}", msg.info);
                    }
                    Msg::Err(msg) => tracing::error!("server returned error; error = {:?}", msg),
                    _ => (),
                }
            }
            Some(Err(e)) => {
                tracing::error!(
                    "an error occurred while processing messages; error = {:?}",
                    e
                    );
                }
            None => break,
            }
        }
    }

    Ok(())
}
