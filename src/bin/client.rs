use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_util::codec::{Framed, LinesCodec};

use futures::SinkExt;
use std::env;
use std::error::Error;
use std::io;
use std::thread;

use lib_sig::crypto::State;
use lib_sig::message::{EncryptedMessage, Message};

fn name_state(n: usize) -> (String, String, State) {
    if n == 1 {
        ("Bob".to_owned(), "Alice".to_owned(), State::init_bob())
    } else {
        ("Alice".to_owned(), "Bob".to_owned(), State::init_alice())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("chat=info".parse()?))
        .with_span_events(FmtSpan::FULL)
        .init();

    let arg0 = env::args().nth(1).unwrap_or_else(|| 0.to_string());

    let client: usize = arg0.parse::<usize>().unwrap();
    let (name, other_name, mut state) = name_state(client);

    let addr = env::args()
        .nth(2)
        .unwrap_or_else(|| "127.0.0.1:6142".to_string());

    let stream = TcpStream::connect(addr).await?;

    let (tx, mut rx) = mpsc::unbounded_channel();

    // separate thread for getting input from stdio
    // sends it through channel to main thread that asynchronously processes it,
    // encrypts it and serialized sends it to server
    thread::spawn(move || loop {
        let mut buf = String::new();
        io::stdin().read_line(&mut buf).unwrap();
        tx.send(buf).unwrap();
    });

    let mut lines = Framed::new(stream, LinesCodec::new());
    lines.send(&name).await?;

    loop {
        tokio::select! {
        Some(msg) = rx.recv() => {
            let msg = Message::new(msg.to_owned(), name.clone(), other_name.clone(),
                state.key_pair().public());
            let (msg, new_state) = msg.encrypt(&state).unwrap();
            state = new_state;
            let msg = serde_json::to_string(&msg).unwrap();
            tracing::debug!("sending message to server: {}", msg);
            lines.send(&msg).await?;
        }

        result = lines.next() => match result {
            Some(Ok(msg)) => {
                let msg: EncryptedMessage = serde_json::from_str(&msg).unwrap();

                let (msg, new_state) = msg.decrypt(&state).unwrap();

                state = new_state;
                print!("{}: {}", msg.sender_name, msg.msg);
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
