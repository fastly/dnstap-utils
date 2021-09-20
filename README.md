# dnstap-utils

A collection of [dnstap](https://dnstap.info/) utilities implemented using the
Rust programming language.

## `dnstap-replay`

`dnstap-replay` is a dnstap collection server which receives dnstap
messages from one or more DNS nameservers and replays them against a
target nameserver.  The responses from the target nameserver are
compared against the originally logged response messages and any
***mismatches*** are made available in dnstap format via an HTTP
endpoint for later analysis.

### `dnstap-replay`: dnstap message requirements

The only type of dnstap log payload that `dnstap-replay` supports is the
`Message/AUTH_RESPONSE` type. Any other dnstap log payload types will be
silently ignored by `dnstap-replay`.

The following fields are ***required*** to be set in the dnstap log
payload:

 * `query_address`
 * `query_port`
 * `query_message`
 * `response_message`

Typically, dnstap `Message/*_RESPONSE` log payloads do not include both
the `query_message` and `response_message` fields on the assumption that
the query message will be logged separately by a `Message/*_QUERY` log
payload. However, this presents a problem for the replay-and-comparison
phase in `dnstap-replay` because it is not entirely trivial to derive
the original DNS query message given only the DNS response message. In
some cases it may be impossible to recover the original query, for
instance if the query is not a validly formatted DNS message.

For the Knot DNS server, [there is a patch in the issue
tracker](https://gitlab.nic.cz/knot/knot-dns/-/issues/764) to add a
configuration option `responses-with-queries` to the `dnstap` module
that logs ***both*** query and response messages together in the
`Message/AUTH_RESPONSE` log payload type. After applying this patch, the
`mod-dnstap` configuration stanza in `knot.conf` would need to look like
the following to produce dnstap output in the format needed by
`dnstap-replay`:

```
mod-dnstap:
  - id: "default"
    sink: "[...]"
    log-queries: off
    log-responses: on
    responses-with-queries: on
```

### `dnstap-replay`: PROXY support in target nameserver

`dnstap-replay` was originally designed for testing nameservers that may
have source IP address dependent behavior or configuration. When a
dnstap-originated DNS query message is replayed by `dnstap-replay`, the
target nameserver sees the source IP address of the machine running
`dnstap-replay` on the UDP packets containing the replayed query
messages. This may elicit varying DNS response message content from the
target nameserver.

In order to avoid this problem, `dnstap-replay` uses the haproxy
[PROXY](https://www.haproxy.org/download/2.5/doc/proxy-protocol.txt)
protocol to prepend the original source address and source port as
logged in the `query_address` and `query_port` dnstap message fields to
the outgoing DNS query message sent to the target nameserver. This
requires support in the target nameserver. Currently,
[dnsdist](https://blog.powerdns.com/2021/05/11/dnsdist-1-6-0-released/),
[PowerDNS Authoritative
Nameserver](https://github.com/PowerDNS/pdns/pull/10660), and [PowerDNS
Recursor](https://github.com/PowerDNS/pdns/pull/8874) have support for
the PROXY header. Additionally, for Knot DNS, [there is a patch in the
issue tracker](https://gitlab.nic.cz/knot/knot-dns/-/issues/762) that
adds support for the PROXY header.

TODO: Currently the PROXY header is unconditionally added to outgoing
DNS queries. For testing nameservers that are not configured to have
source IP address dependent behavior, it should be possible to omit the
PROXY header.

### `dnstap-replay`: HTTP server

`dnstap-replay` includes a built-in HTTP server to export [Prometheus
metrics](src/bin/dnstap-replay/metrics.rs) which are available at the
`/metrics` HTTP endpoint.

When `dnstap-replay` sends a DNS query to the target nameserver and the
response from the target nameserver does not exactly match the
originally logged response message, a log message containing the
mismatched response message is generated and buffered and can be
retrieved from the `/mismatches` HTTP endpoint. This endpoint drains the
mismatch buffer and provides the output in Frame Streams format
containing dnstap payloads.

The dnstap log messages exported via the `/mismatches` endpoint are the
originally logged dnstap messages received by `dnstap-replay`, with the
dnstap [`extra`
field](https://github.com/dnstap/dnstap.pb/blob/9bafb5b59dacc48a6ff6a839e419e540f1201c42/dnstap.proto#L37-L40)
populated with a serialized version of the error encountered by
`dnstap-replay`. This preserves the original DNS response message as
well as the DNS response message sent by the target nameserver, which
allows for byte-for-byte analysis of the mismatch.

TODO: A tool is needed to decode the dnstap `extra` field so that the
original and mismatched response messages can be compared.

### `dnstap-replay`: Command-line example

`dnstap-replay` requires the `--dns`, `--http`, and `--unix` arguments
to be provided.

The `--dns` argument specifies the IP address and port of the target
nameserver which will receive replayed DNS queries.

The `--http` argument specifies the IP address and port for the built-in
HTTP server.

The `--unix` argument specifies the filesystem path to bind the dnstap
Unix socket to.

Additionally, there are command-line options `--channel-capacity` and
`--channel-mismatch-capacity` which allow tuning of internal buffer
sizes.

For example, the following command-line invocation will listen on the
filesystem path `/run/dnstap.sock` for incoming dnstap connections from
the DNS server(s) that will send dnstap log data and on the TCP socket
127.0.0.1:53080 for incoming HTTP connections. Replayed DNS queries will
be sent to the target nameserver which should be configured to listen on
127.0.0.1:53053.

```
    $ dnstap-replay --dns 127.0.0.1:53053 --http 127.0.0.1:53080 --unix /run/dnstap.sock
```

The Prometheus metrics endpoint can be accessed at
`http://127.0.0.1:53080/metrics`.

The Frame Streams mismatches endpoint can be accessed at
`http://127.0.0.1:53080/mismatches`.

## License

TBD
