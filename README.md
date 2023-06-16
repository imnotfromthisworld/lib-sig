# Simple client and server for encrypted messaging

#### Minimum Supported Rust Version
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
cargo run --bin client <username> [ip]
```
To message other connected clients, use: `<username>><message>`

To list connected clients: `!list`
To show help: `!help`

