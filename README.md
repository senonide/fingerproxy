# 🔎 Fingerproxy 🔒

Fingerprints can be used for bot detection, DDoS mitigation, client identification, etc. To use these fingerprints, just extract the HTTP request headers in your backend apps.

Fingerproxy is also a Go library, which allows users implementing their own fingerprinting algorithm.

## Usage

> [!TIP]
> Try fingerproxy in 1 minute:

First of all, run the following commands:
```bash
make prepare
make run-test
```

We are ready to go. Send an HTTPS request to fingerproxy:
```bash
curl "https://localhost:8443/anything" --insecure | jq
```
You will see fingerprints in request headers:
```json
{
  "args": {},
  "headers": {
    "Accept": [
      "*/*"
    ],
    "Accept-Encoding": [
      "gzip"
    ],
    "Host": [
      "httpbin.io"
    ],
    "User-Agent": [
      "curl/8.9.1"
    ],
    "X-Forwarded-For": [
      "::1"
    ],
    "X-Forwarded-Host": [
      "localhost:8443"
    ],
    "X-Forwarded-Proto": [
      "https"
    ],
    "X-Http2-Fingerprint": [
      "3:100;4:10485760;2:0|1048510465|0|m,s,a,p" // Akamai HTTP2 fingerprint
    ],
    "X-Ja3-Fingerprint": [
      "1ee96c96da0a44dc79c063f3d88105f5" // JA3 fingerprint with shorted cipher suites
    ],
    "X-Ja4-Fingerprint": [
      "t13d3613h2_018971650b2c_03eb65375a95" // JA4 fingerprint
    ]
  },
  "method": "GET",
  "origin": "::1",
  "url": "https://httpbin.io/anything",
  "data": "",
  "files": {},
  "form": {},
  "json": null
}
```

## Production-Ready

The fingerproxy binary is production-ready. [Subscan.io](https://www.subscan.io/) has 12 fingerproxy instances running in the production environment, which process almost 40,000,000 requests/day on average.

Unit tests, memory usage tests, E2E tests, and benchmarks have been implemented and run on GitHub Actions.

And of course, fingerproxy follows SemVer.

## Implement Your Fingerprinting Algorithm

Check out the examples [`ja3-raw`](example/ja3-raw/) or [`my-fingerprint`](example/my-fingerprint/). No code fork needed.

## Chrome JA3 Fingerprints Change Every Time

Yes, it is an known issue of the original JA3 implementation. See [Google Chrome TLS extension permutation](https://github.com/net4people/bbs/issues/220). Sorting the TLS extension is one method to avoid the affect of this feature. Here is an example [ja3-sorted-extensions](example/ja3-sorted-extensions/).

## Use as a Library

Fingerproxy is degigned to be highly customizable. It is separated into serveral packages. You can find all packages in the [`pkg`](pkg/) dir and use them to build your own fingerprinting server.

Here is an example [`echo-server`](example/echo-server/). Instead of forwarding HTTP requests, it simply responds back to client with the fingerprints.

## References

- JA3 fingerprint: <https://github.com/salesforce/ja3>
- JA4 fingerprint: <https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md>
- Akamai HTTP2 fingerprinting: <https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf>
