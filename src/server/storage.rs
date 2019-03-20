use futures::future::{self, Future, IntoFuture};
use crate::server::{Code, UserInfo};
use futures_locks::RwLock;
use std::time::Instant;
use quick_error::quick_error;

#[derive(Debug)]
pub struct StorageError {
    inner: Box<dyn std::error::Error>
}

impl StorageError {
    pub fn new<E: std::error::Error + 'static>(e: E) -> Self {
        Self {
            inner: Box::new(e)
        }
    }
}

impl<T: std::error::Error + 'static> std::convert::From<T> for StorageError {
    fn from(e:T) -> Self {
        Self::new(e)
    }
}

// TODO: change this when trait method can return impl trait
// trait StorageFuture<T> = future::Future<T, Error=StorageError>;
type StorageFuture<T> = Box<dyn Future<Item=T, Error=StorageError>>;

pub type Identity = usize;

#[derive(Clone)]
pub struct StorageEntry {
    code: Code,
    user_info: UserInfo,
    add_time: Instant
}

pub trait SessionStorageHandle : Send + Sync {
    fn store(&mut self, entry: StorageEntry) -> StorageFuture<Identity>;
    fn get(&mut self, id: Identity) -> StorageFuture<StorageEntry>;
    //fn get_code(&self, id: Identity) -> StorageFuture<Code>;
    //fn get_grant_info(&self, id: Identity) -> StorageFuture<GrantInfo>;
    fn len(& self) -> StorageFuture<usize>;
    fn clear(&mut self) -> StorageFuture<()>;
    fn hint_trim(&mut self) -> StorageFuture<()>;
    fn trim(&mut self, inst: Instant) -> StorageFuture<()>;
}

#[derive(Clone)]
pub struct InprocessStorageHandle {
    inner: RwLock<InprocessStorageInner>,
}

impl InprocessStorageHandle {
    pub fn new() -> Self {
        InprocessStorageHandle {
            inner: RwLock::new(InprocessStorageInner::new())
        }
    }
}

// TODO: write some macro to simplify this
impl SessionStorageHandle for InprocessStorageHandle {
    fn store(&mut self, entry: StorageEntry) -> StorageFuture<Identity> {
        Box::new(self.inner.write().map_err(|_| { log::info!("inprocess_store_error"); InprocessStorageError::FailedToWriteLock } ).and_then(move |mut res| {
            future::ok(res.store(entry))
        }).from_err())
    }

    fn get(&mut self, id: Identity) -> StorageFuture<StorageEntry> {
        Box::new(self.inner.write().map_err(|_| {log::info!("inprocess_get_error"); InprocessStorageError::FailedToReadLock }).and_then(move |mut res| {
            res.get(id).ok_or(InprocessStorageError::FailToFindKey).into_future()
        }).from_err())
    }

    fn len(&self) -> StorageFuture<usize> {
        Box::new(self.inner.read().into_future().map_err(|_| { log::info!("inprocess_storage_len_error"); InprocessStorageError::FailedToReadLock }).and_then(move |res| {
            future::ok(res.len())
        }).from_err())
    }

    fn clear(&mut self) -> StorageFuture<()> {
        Box::new(self.inner.write().map_err(|_| { log::info!("inprocess_storage_clear_error"); InprocessStorageError::FailedToWriteLock } ).and_then(move |mut res| {
            future::ok(res.clear())
        }).from_err())
    }

    fn hint_trim(&mut self) -> StorageFuture<()> {
        Box::new(self.inner.write().map_err(|_| { log::info!("inprocess_storage_hint_trim_error"); InprocessStorageError::FailedToWriteLock }).and_then(move |mut res| {
            future::ok(res.hint_trim())
        }).from_err())
    }

    fn trim(&mut self, inst: Instant) -> StorageFuture<()> {
        Box::new(self.inner.write().map_err(|_| { log::info!("inprocess_storage_trim_error"); InprocessStorageError::FailedToWriteLock}).and_then(move |mut res| {
            future::ok(res.trim(inst))
        }).from_err())
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum InprocessStorageError {
        FailToFindKey {}
        FailedToReadLock {}
        FailedToWriteLock {}
    }
}

type LruCache = lru_cache::LruCache<Identity, StorageEntry>;
struct InprocessStorageInner(LruCache);

impl InprocessStorageInner {
    pub fn new() -> Self {
        InprocessStorageInner(LruCache::new(4096))
    }

    pub fn store(&mut self, entry: StorageEntry) -> Identity {
        let id = self.len();
        self.0.insert(id, entry);
        id
    }

    pub fn get(&mut self, id: Identity) -> Option<StorageEntry> {
        self.0.get_mut(&id).map(|st| { st.clone() } )
    }

    //fn get_code(&self, id: Identity) -> StorageFuture<Code>;
    //fn get_grant_info(&self, id: Identity) -> StorageFuture<GrantInfo>;
    fn len(& self) -> usize {
        self.0.len()
    }

    fn clear(&mut self) {
        self.0.clear();
    }

    fn hint_trim(&mut self) {
        self.0.clear();
    }

    fn trim(&mut self, _inst: Instant) {
        self.0.clear();
    }
}

pub struct RedisStorageHandle {
}

pub struct PostgresStorageHandle {
}
