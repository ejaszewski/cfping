cfping
======

`cfping` is a small command line ping program written for the Cloudflare
2020 Remote Summer Internship application. It is written in [Rust], using
[libpnet] to handle constructing and sending ICMP requests, and [structopt]
for the CLI.

Architecture
------------

`cfping` uses two threads, one for sending packets, and one for receiving
them. Ping timing is handled entirely on the client side. Specifically,
packet sending is handled in a thread that gets spawned, while receiving is
handled in the main thread. ICMP echo request times get stored in a map, and
get removed as soon as a request with the same sequence number is received.
Statistics are calculated online, so only pending echo requests are stored.
An interrupt handler is set up to print more detailed statistics on exit.

Options
-------

In addition to the required `DESTINATION` argument, the command also supports
optional arguments to specify the packet size, IP time to live, and the
time interval between packets.

[Rust]: https://www.rust-lang.org
[libpnet]: https://github.com/libpnet/libpnet
[structopt]: https://github.com/TeXitoi/structopt