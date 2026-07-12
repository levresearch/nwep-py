# nwep python examples

each example is a self-contained, runnable program that reproduces a sandbox
dogfood app's protocol surface over the real quic transport  -  the same validation
discipline the rust binding follows, so "the binding works" means "it reproduced
the dogfood apps". every example here is run as a subprocess by
`tests/test_examples.py`, so an example that rots is a failing test.

run one from the `bindings/python` directory:

```sh
PYTHONPATH=examples:. python examples/nwkv.py
```

(the examples import `_common` from this directory; pointing `PYTHONPATH` at both
this dir and the package root is all the setup they need. set `NWEP_LIB_DIR` if the
built library is not under `zig-out/lib`.)

| example | mirrors | shows |
|---|---|---|
| `identity.py` |  -  | keygen, node_id base58 round trip, key binding, signature verify |
| `managed.py` |  -  | the managed (L2) asyncio quickstart: `serve()` + `connect_async()`, no loop |
| `managed_dht.py` |  -  | the managed dht: a runtime-owned dht, `resolve(node_id)` is one await |
| `managed_stream.py` |  -  | the managed stream: `ClientBuilder.stream()` pulls a large body async, trailer verified |
| `nwkv.py` | 000-nwkv | key-value write/read/delete + a notify push drained by `poll_notify` |
| `nwserve.py` | 001-nwserve | content path: etag, conditional reads (6.7), byte ranges (6.8) |
| `nwlog.py` | 002-nwlog | merkle log + log-server router, signed key-binding submit/decode |
| `nwcurl.py` | 003-nwcurl | client surface: header iteration (curl -i), verify (-k), streaming |
| `nwproxy.py` | 004-nwproxy | caching reverse proxy: defer + relay + shared signed cache |
| `nwdrop.py` | 005-nwdrop | the no-dns headline: dht discover-by-node_id + resumable ranged download |

the trust layer (bls, checkpoint, trust store, anchor) is exercised by the
trust `tests/` suites  -  which run by default, since the bindings ship the full
`libnwep.so`  -  not the examples, since it has no standalone single-process dogfood
app.
