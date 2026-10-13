# @openvtc/vti-rooms-wasm

A data room's member half for the browser, compiled from the
[`vti-rooms-wasm`](https://github.com/OpenVTC/verifiable-trust-infrastructure/tree/main/vti-rooms-wasm)
crate: MLS group custody, record sealing, the epoch key chain, and room files
(`FileSealer` / `FileOpener`), running the same code as the VTA, the CLI and
the hosts' conformance tests.

Built with `wasm-bindgen --target bundler`, for a bundler that imports
WebAssembly as ESM (Vite with `vite-plugin-wasm`, webpack 5 with
`asyncWebAssembly`).

## Room files and their keys

`FileSealer.withKey` and `FileOpener.withKey` take one file's key, released by
the member's VTA (`rooms/keys/file-key/0.1`). **Call them only in a context that
is yours and not a web page's** — a wallet extension's offscreen document or
service worker. A file key never expires: a page that held one would hold that
file's ciphertext open forever, and on a public store such as Walrus that
ciphertext is public forever.

What `FileOpener.push` returns is provisional. Release plaintext (save it,
render it, hand it on) only once `finish()` has returned and `verified` is
`true`; on any error, discard what was written.

The design is `docs/05-design-notes/data-rooms-files.md` §3–4 in the repository.

## Building

`scripts/build-rooms-wasm-npm.sh` in the repository builds this package. It
needs the `wasm-bindgen` CLI at the version `Cargo.lock` pins.
