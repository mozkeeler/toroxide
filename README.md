toroxide
-----
`toroxide` is an experimental, proof-of-concept implementation of the client side of the Tor protocol in Rust. You should not rely on it to protect your anonymity (in fact, it probably can't even connect to the real Tor network at the moment).

Building and Running
-----
Clone and build Tor:
```
git clone https://git.torproject.org/tor
cd tor
./configure --disable-asciidoc
make -j8
```

Clone chutney and start a local test Tor network:
```
git clone https://git.torproject.org/chutney
cd chutney
CHUTNEY_TOR=<path/to>/tor/src/or/tor CHUTNEY_TOR_GENCER=<path/to>/tor/src/tools/tor-gencert ./chutney setup networks/basic
CHUTNEY_TOR=<path/to>/tor/src/or/tor CHUTNEY_TOR_GENCER=<path/to>/tor/src/tools/tor-gencert ./chutney configure networks/basic
CHUTNEY_TOR=<path/to>/tor/src/or/tor CHUTNEY_TOR_GENCER=<path/to>/tor/src/tools/tor-gencert ./chutney start networks/basic
```

Clone, build and run toroxide:
```
git clone https://github.com/mozkeeler/toroxide.git
cd toroxide
cargo build
cargo run -- localhost:7000
```
(the chutney network defined in networks/basic starts a directory server at localhost:7000)

If all goes according to plan, you should see some output that suggests toroxide successfully connected to the test network, set up a circuit, and made an end-to-end request.
