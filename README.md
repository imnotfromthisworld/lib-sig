# Minimum Supported Rust Version
Rust **1.56** or higher.


# Getting started
```
$ git clone https://github.com/imnotfromthisworld/lib-sig.git
$ cd lib-sig
```

# Building/running
## Server
```
cargo run --bin server [ip]
```
By default the IP address is set to `127.0.0.1:6142`

## Client
```
cargo run --bin client <client_type> [ip]
```
Currently there are _two_ clients for demo purposes, Alice and Bob.

To run client as Alice use `cargo run --bin client 0`

To run client as Bob use `cargo run --bin client 1`

In order to send messages, Alice needs to initiate the conversation, which
synchronizes the states and both parties can message each other. If Bob starts
the conversation first, he crashes.

