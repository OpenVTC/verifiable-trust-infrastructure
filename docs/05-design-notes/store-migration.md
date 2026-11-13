# Store Abstraction: Migration Path to Traits

Status: **not started** — `Store` (`vti-common/src/store/mod.rs`) is still the enum this note proposes replacing with traits.

## Current design: Enum dispatch

`Store` and `KeyspaceHandle` in `vti-common/src/store/mod.rs` are enums:

```rust
pub enum Store {
    Local(LocalStore),       // fjall on local filesystem
    Vsock(VsockStore),       // vsock-proxied to parent EC2
}

pub enum KeyspaceHandle {
    Local(LocalKeyspaceHandle),
    Vsock(VsockKeyspaceHandle),
}
```

Every method on `KeyspaceHandle` has a `match` dispatch:

```rust
pub async fn get<V>(&self, key: impl Into<Vec<u8>>) -> Result<Option<V>, AppError> {
    match self {
        KeyspaceHandle::Local(h) => h.get(key).await,
        KeyspaceHandle::Vsock(h) => h.get(key).await,
    }
}
```

## Why enum (not trait)

The enum was chosen because:
1. **No dynamic dispatch overhead** -- no `Box<dyn>` or vtable
2. **Zero call-site changes** -- all 26+ files use `KeyspaceHandle` directly
3. **Two variants only** -- manageable boilerplate

## When to migrate to traits

Migrate when a **third storage backend** is needed (e.g., PostgreSQL,
DynamoDB, S3-backed). At that point the enum boilerplate becomes untenable
(~100 lines of dispatch per variant, growing linearly).

## Migration steps

### 1. Define the trait

```rust
#[async_trait]
pub trait KvStore: Send + Sync + Clone {
    async fn insert_raw(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), AppError>;
    async fn get_raw(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>, AppError>;
    async fn remove(&self, key: Vec<u8>) -> Result<(), AppError>;
    async fn prefix_iter_raw(&self, prefix: Vec<u8>) -> Result<Vec<(Vec<u8>, Vec<u8>)>, AppError>;
    async fn prefix_keys(&self, prefix: Vec<u8>) -> Result<Vec<Vec<u8>>, AppError>;
    async fn approximate_len(&self) -> Result<usize, AppError>;
}
```

### 2. Separate encryption from storage

Currently encryption is baked into each handle type. Extract it:

```rust
pub struct EncryptedStore<T: KvStore> {
    inner: T,
    key: [u8; 32],
}
```

This wrapper encrypts before delegating to the inner store.

### 3. Replace the enum with `Arc<dyn KvStore>`

```rust
pub type KeyspaceHandle = Arc<dyn KvStore>;
```

Or keep the wrapper for the `insert<V: Serialize>` convenience methods:

```rust
pub struct KeyspaceHandle {
    inner: Arc<dyn KvStore>,
}
```

### 4. Update call sites

With the wrapper approach, call sites don't change at all -- `KeyspaceHandle`
keeps the same method signatures.

### 5. Adding a new backend

With traits, adding a new backend requires only:
1. Implement `KvStore` for the new type (~60 lines)
2. No changes to the dispatch enum or existing backends
3. The front-end binary constructs the appropriate type

## Estimated effort

- Trait definition + encryption wrapper: ~100 lines
- LocalKeyspaceHandle `impl KvStore`: ~80 lines (extract from existing)
- VsockKeyspaceHandle `impl KvStore`: ~80 lines (extract from existing)
- Remove enum dispatch: ~-200 lines
- Call site changes: 0 (if using wrapper)
- **Net: ~60 lines of new code, ~200 lines removed**
