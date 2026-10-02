# Shared Auth web-server PR 37 certification

Independent exact-head certification for `shared-auth/shared-auth-web-server.rs#37` at product head `8d0c7d48b0ad43bee48142661a9f7b8b1dde2594`.

This cert fetches the public product commit by immutable SHA and executes the source repository's own stable-Rust format, strict Clippy, and all-feature test gates. It also asserts that the request-time consumer-policy enforcement points are actually present in `main.rs`, `state.rs`, and `http_server.rs`.

The product head pins `shared-auth-lib-core` commit `a44b803fb8c063da8c27e2a14603a850d2711c12`, the exact dependency under independent certification in the companion task-6 evidence PR.
