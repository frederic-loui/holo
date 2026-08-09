## Installation

### Build from source

1. Install the Rust toolchain

If you don't already have Rust in your system, the best way to install it is via [rustup](https://rustup.rs/).

2. Clone Holo's git repositories

```
$ git clone https://github.com/holo-routing/holo.git
$ git clone https://github.com/holo-routing/holo-cli.git
```

3. Install build dependencies:

Holo requires a few dependencies for building and embedding the libyang library.
You can install them using your system's package manager. For example, on Debian-based systems:

```
# apt-get install build-essential cmake libpcre2-dev protobuf-compiler
```

4. Build `holod` and `holo-cli`

```
$ cd holo/
$ cargo build --release
$ cd ../holo-cli/
$ cargo build --release
```

5. Add the `holo` user, plus the `holo` and `holoadm` groups:

```sh
# groupadd -r holo
# groupadd -r holoadm
# useradd --system --shell /sbin/nologin --home-dir /var/opt/holo/ -g holo holo
# mkdir /var/opt/holo /var/log/holo
# chown holo:holoadm /var/opt/holo /var/log/holo
# chmod 0750 /var/opt/holo /var/log/holo
```

`holod` runs as the `holo` user and the `holoadm` group, so the log files, the database and the gRPC local socket are all group-owned by `holoadm`.
Its members get the access `holo-cli` needs without being root, so membership amounts to full administrative access to the router.

6. Installation

Copy the `holod` and `holo-cli` binaries from the `target/release` directories to your preferred location.

Alternatively, you can use `cargo install` to install these binaries into the `$HOME/.cargo/bin` directory.

## Configuration

`holod` configuration consists of the following:
* `/etc/holod.toml`: static configuration that can't change once the daemon starts. It's meant to configure which features are enabled, plugins parameters, among other things.
  Here's an [example](holo-daemon/holod.toml) containing the default values. If this file doesn't exist, the default values will be used.
* Running configuration: this is the normal YANG-modeled
configuration that can only be changed through a northbound client
(e.g. [gRPC](https://github.com/holo-routing/holo/wiki/gRPC),
[gNMI](https://github.com/holo-routing/holo/wiki/gNMI),
[CLI](https://github.com/holo-routing/holo/wiki/CLI), etc).

### Remote access (optional)

By default, the gRPC plugin listens on a local Unix socket and the gNMI plugin is disabled.
Access to the socket is granted by its file permissions, and no password is required.

When a plugin listens on a TCP address, clients must authenticate as a user configured under `/ietf-system:system/authentication/user`, providing its name and password with every request.
Both plugins always require TLS on a TCP address, since those credentials would otherwise be transmitted in clear text.
The remainder of this section describes how to provision the required certificate and key.

Create a certificate authority for the network:
```sh
$ openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=example-ca" \
    -keyout ca.key -out ca.pem
```

Issue a certificate for each router.
The first command runs on the router, so that the private key never leaves the device, and the second on the system holding the CA key:
```sh
$ openssl req -newkey rsa:2048 -nodes -subj "/CN=rtr1" -keyout holo.key -out holo.csr
$ openssl x509 -req -in holo.csr -CA ca.pem -CAkey ca.key -days 825 -out holo.pem \
    -extfile <(printf "subjectAltName=DNS:rtr1.example.net,IP:198.51.100.1")
```

The `subjectAltName` must include the address or name that clients connect to, otherwise certificate validation fails.

`holod` reads the certificate and the key after dropping privileges, so both must be readable by the `holo` user:
```sh
# mkdir /etc/holo
# install -o holo -m 0400 holo.key /etc/holo/holo.key
# install -m 0444 holo.pem /etc/holo/holo.pem
```

Enable the desired plugin in `/etc/holod.toml`, and verify its TCP listening address and certificate paths.
Clients require `ca.pem` to validate the router certificate, along with the name and password of a configured user.

#### Validating the setup with gnmic

Retrieving state over gNMI:
```sh
$ gnmic -a 198.51.100.1:9339 -u alice -p secret --tls-ca /etc/holo/ca.pem \
    --encoding json_ietf get --path /ietf-routing:routing
```

Those settings can be kept in a `gnmic` configuration file instead:
```yaml
username: alice
password: secret
tls-ca: /etc/holo/ca.pem
encoding: json_ietf
```

`gnmic` reads `~/.gnmic.yaml` by default, reducing the command above to `gnmic -a 198.51.100.1:9339 get --path /ietf-routing:routing`.
It is also the safer option, since command-line arguments can be read by any local user, whereas the file is protected by its permissions.
