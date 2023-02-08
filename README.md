# dnstap-utils

A collection of [dnstap] utilities implemented using the Rust
programming language.

[dnstap]: https://dnstap.info/

## `dnstap-replay`

`dnstap-replay` is a dnstap collection server which receives dnstap
messages from one or more DNS nameservers and replays them against a
target nameserver.  The responses from the target nameserver are
compared against the originally logged response messages and any
***mismatches*** or other errors are made available in dnstap format
via an HTTP endpoint for later analysis.

### `dnstap-replay`: dnstap message requirements

`dnstap-replay` was designed for testing authoritative nameservers. The
only type of dnstap log payload that `dnstap-replay` supports is the
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

For the Knot DNS server, [support was added in version 3.1.4] to add a
configuration option `responses-with-queries` to the `dnstap` module
that logs ***both*** query and response messages together in the
`Message/AUTH_RESPONSE` log payload type. The `mod-dnstap` configuration
stanza in `knot.conf` would need to look like the following to produce
dnstap output with the fields needed by `dnstap-replay`:

```
mod-dnstap:
  - id: "default"
    sink: "[...]"
    log-queries: off
    log-responses: on
    responses-with-queries: on
```

[support was added in version 3.1.4]: https://gitlab.nic.cz/knot/knot-dns/-/issues/764

### `dnstap-replay`: PROXY support in target nameserver

`dnstap-replay` was originally designed for testing nameservers that may
have source IP address dependent behavior or configuration. When a
dnstap-originated DNS query message is replayed by `dnstap-replay`, the
target nameserver sees the source IP address of the machine running
`dnstap-replay` on the UDP packets containing the replayed query
messages. This may elicit varying DNS response message content from the
target nameserver.

In order to avoid this problem, `dnstap-replay` can use the haproxy
[PROXY] protocol to prepend the original source address and source port
as logged in the `query_address` and `query_port` dnstap message fields
to the outgoing DNS query message sent to the target nameserver. This
requires support in the target nameserver. Currently, at least
[dnsdist], [PowerDNS Authoritative Nameserver], [PowerDNS Recursor], and
[Knot DNS] have support for the PROXY header.

To enable this functionality in `dnstap-replay`, add the `--proxy`
option to the command-line parameters.

Support for PROXYv2 as a connection target was added in Knot DNS version
3.2.2, which adds a configuration option [`proxy_allowlist`] that lists
the IP addresses that are allowed to initiate queries with the PROXYv2
header. It is enabled by placing the option in the `server`
configuration stanza, for instance:

```
server:
    […]
    proxy-allowlist: 127.0.0.0/8
```

[PROXY]: https://www.haproxy.org/download/2.5/doc/proxy-protocol.txt
[dnsdist]: https://blog.powerdns.com/2021/05/11/dnsdist-1-6-0-released/
[PowerDNS Authoritative Nameserver]: https://github.com/PowerDNS/pdns/pull/10660
[PowerDNS Recursor]: https://github.com/PowerDNS/pdns/pull/8874
[Knot DNS]: https://gitlab.nic.cz/knot/knot-dns/-/merge_requests/1468
[`proxy_allowlist`]: https://www.knot-dns.cz/docs/3.2/html/reference.html?highlight=proxy#proxy-allowlist

### `dnstap-replay`: HTTP server

`dnstap-replay` includes a built-in HTTP server to export [Prometheus
metrics] which are available at the `/metrics` HTTP endpoint.

When `dnstap-replay` sends a DNS query to the target nameserver and the
response from the target nameserver does not exactly match the
originally logged response message, a log message containing the
mismatched response message is generated and buffered in memory and can
be retrieved from the `/errors` HTTP endpoint. This endpoint drains the
error buffer and provides the output in Frame Streams format containing
dnstap payloads.

The dnstap log messages exported via the `/errors` endpoint are the
originally logged dnstap messages received by `dnstap-replay`, with the
[dnstap `extra` field] populated with a serialized version of the error
encountered by `dnstap-replay`. This preserves the original DNS response
message as well as the DNS response message sent by the target
nameserver, which allows for byte-for-byte analysis of the mismatch.

A separate `/timeouts` endpoint is available which can be used to
retrieve dnstap log messages that resulted in timeouts when re-querying
the target nameserver. The format used is the same as the `/errors`
endpoint.

[Prometheus metrics]: https://github.com/fastly/dnstap-utils/blob/main/src/bin/dnstap-replay/metrics.rs
[dnstap `extra` field]: https://github.com/dnstap/dnstap.pb/blob/9bafb5b59dacc48a6ff6a839e419e540f1201c42/dnstap.proto#L37-L40

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
`--channel-error-capacity` which allow tuning of internal buffer
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

The Frame Streams "errors" endpoint can be accessed at
`http://127.0.0.1:53080/errors`.

The Frame Streams "timeouts" endpoint can be accessad at
`http://127.0.0.1:53080/timeouts`.

## `dnstap-dump`

`dnstap-dump` is a utility which dumps a Frame Streams formatted dnstap
file to YAML. The output format is very similar to the format generated
by the [`dnstap-ldns`] utility.

It has support for decoding the `extra` field in dnstap error payloads
produced by `dnstap-replay`, and it also dumps DNS wire messages in
hex-encoded wire format as well as in dig-style output.

[`dnstap-ldns`]: https://github.com/dnstap/dnstap-ldns

## `fmt-dns-message`

`fmt-dns-message` is a utility which converts a hex-encoded wire format
DNS message to dig-style output using the [NLnet Labs `domain` crate].

[NLnet Labs `domain` crate]: https://github.com/NLnetLabs/domain

## License

`dnstap-utils` is distributed under the terms of the [Apache-2.0]
license. See the [LICENSE] and [NOTICE] files for details.

[Apache-2.0]: https://www.apache.org/licenses/LICENSE-2.0
[LICENSE]: https://github.com/fastly/dnstap-utils/blob/main/LICENSE
[NOTICE]: https://github.com/fastly/dnstap-utils/blob/main/NOTICE
