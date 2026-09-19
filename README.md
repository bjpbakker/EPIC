# EPIC: Erik Protocol Implementation Concept

## Getting Started

You need the rust toolchain (rustc and cargo) installed. Then build and run.

```
# cargo build
# cargo test
# cargo run
```

You can use the `erik_fetch` tool to interact with an ERIK relay.

```
# cargo run --bin erik_fetch -- --fqdn <fqdn> --server <erik-relay> index
```

## Development Progress

### Server Mode

#### Simple mode: Proxy of trusted RRDP repoistory

[x] Run server with in memory cache (epic binary)
[x] Get updates from a single RRDP source
[x] Serve index
[x] Serve partitions
[x] Serve binary objects
[ ] Serve snapshot
[ ] Serve Segment/-Index

#### Advanced Improvements
[ ] Use key-value store with overflow to disk (foyer, sqlite?)
[ ] Support multiple RRDP sources
[ ] Support rsync sources
[ ] Erik Proxy mode: fetch from other Erik Relays and make available
[ ] Get and serve Trust Anchors (validated self-signed certificates + tiebreaker)

#### Very advanced.. add dedicated and embedded validator

[ ] Use dedicated binary or mode?
[ ] Validate TA
[ ] Async / dispatch discovery and fetching repos
[ ] Validate & tiebreak discovered manifest before inclusion in store
[ ] Schedule re-fetching of repos
[ ] Trigger validation on changes
[ ] Validate TA tree
[ ] Possibly: archive unused repos
[ ] Possibly: back-off unresponsive repos

### Client Code

[x] Simple client binary for debugging (erik_fetch)
[x] Get index
[x] Get partition
[ ] Get object
[ ] Get snapshot
[ ] Get segments