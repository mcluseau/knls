use crate::kube_watch::Change;
use core::ops::RangeBounds;
use std::collections::{BTreeMap, BTreeSet, HashMap, btree_map, hash_map::Entry};
use std::hash::Hash;

/// Fallible conversion of a watched object into a [`Store`] key.
///
/// Not every watched object maps to a key — an EndpointSlice without the
/// `kubernetes.io/service-name` label has no key — so unlike [`Into`] this may
/// yield `None`; such objects are skipped by [`Store::ingest`].
pub trait IntoKey<T> {
    fn into_key(t: &T) -> Option<Self>
    where
        Self: Sized;
}

pub struct Store<K, V> {
    ready: bool,
    map: BTreeMap<K, V>,
}

impl<K, V> Default for Store<K, V> {
    fn default() -> Self {
        Self {
            ready: false,
            map: BTreeMap::new(),
        }
    }
}

impl<K: Ord, V> Store<K, V> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_ready(&self) -> bool {
        self.ready
    }

    /// ingest a watcher event
    ///
    /// Objects that do not convert to a key (e.g. an EndpointSlice without the
    /// `kubernetes.io/service-name` label) are skipped.
    ///
    /// This assumes a key, once derivable, stays derivable: a keyless object
    /// that later gains a key is handled (it is inserted), but a keyed object
    /// that later loses its key is not (its old entry is left behind, since the
    /// old key cannot be recovered from the new object).
    pub fn ingest<T>(&mut self, event: &Change<T>)
    where
        K: IntoKey<T>,
        for<'t> &'t T: Into<V>,
    {
        use Change::*;
        match event {
            Init => {
                self.ready = false;
            }
            InitDone => {
                self.ready = true;
            }
            InitApply(o) | Apply(o) => {
                if let Some(key) = K::into_key(o.as_ref()) {
                    self.map.insert(key, o.as_ref().into());
                }
            }
            Delete(o) => {
                if let Some(key) = K::into_key(o.as_ref()) {
                    self.map.remove(&key);
                }
            }
        }
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key)
    }

    pub fn range<R>(&self, range: R) -> btree_map::Range<'_, K, V>
    where
        R: RangeBounds<K>,
    {
        self.map.range(range)
    }
}

pub struct HashIndex<T, K, V> {
    ready: bool,
    #[allow(clippy::type_complexity)]
    get_values: Box<dyn Fn(&T) -> BTreeSet<V> + Send + Sync>,
    k2v: HashMap<K, BTreeSet<V>>,
    v2k: HashMap<V, BTreeSet<K>>,
}

impl<T, K, V> HashIndex<T, K, V>
where
    K: for<'t> From<&'t T>,
    K: Ord + Hash + Clone,
    V: Ord + Hash + Clone,
{
    pub fn new(get_values: impl Fn(&T) -> BTreeSet<V> + Send + Sync + 'static) -> Self {
        Self {
            ready: false,
            get_values: Box::new(get_values),
            k2v: HashMap::new(),
            v2k: HashMap::new(),
        }
    }

    pub fn get(&self, k: &K) -> Option<&BTreeSet<V>> {
        self.k2v.get(k)
    }
    pub fn get_rev(&self, v: &V) -> Option<&BTreeSet<K>> {
        self.v2k.get(v)
    }

    pub fn insert(&mut self, k: K, vs: BTreeSet<V>) {
        for v in self.k2v.get(&k).cloned().into_iter().flatten() {
            self.remove_v2k(&k, v);
        }
        for v in vs.iter().cloned() {
            self.v2k.entry(v).or_default().insert(k.clone());
        }
        self.k2v.insert(k, vs);
    }

    pub fn remove(&mut self, k: &K) {
        for v in self.k2v.remove(k).into_iter().flatten() {
            self.remove_v2k(k, v);
        }
    }

    fn remove_v2k(&mut self, k: &K, v: V) {
        if let Entry::Occupied(mut e) = self.v2k.entry(v) {
            let keys = e.get_mut();
            keys.remove(k);
            if keys.is_empty() {
                e.remove();
            }
        }
    }

    pub fn is_ready(&self) -> bool {
        self.ready
    }

    /// ingest a watcher event
    pub fn ingest(&mut self, event: &Change<T>) {
        use Change::*;
        match event {
            Init => {
                self.ready = false;
            }
            InitDone => {
                self.ready = true;
            }
            InitApply(o) | Apply(o) => {
                self.insert(o.as_ref().into(), (self.get_values)(o));
            }
            Delete(o) => {
                self.remove(&o.as_ref().into());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// An object whose key conversion can fail, like an EndpointSlice not owned
    /// by a Service.
    struct Item(Option<u32>);

    impl IntoKey<Item> for u32 {
        fn into_key(i: &Item) -> Option<u32> {
            i.0
        }
    }

    impl From<&Item> for u32 {
        fn from(i: &Item) -> u32 {
            i.0.unwrap_or_default()
        }
    }

    #[test]
    fn ingest_skips_unconvertible() {
        let mut store: Store<u32, u32> = Store::new();

        store.ingest(&Change::InitApply(Arc::new(Item(Some(1)))));
        store.ingest(&Change::Apply(Arc::new(Item(Some(2)))));
        assert_eq!(store.get(&1), Some(&1));
        assert_eq!(store.get(&2), Some(&2));

        // an unconvertible object is skipped, not inserted
        store.ingest(&Change::Apply(Arc::new(Item(None))));
        assert_eq!(store.range(..).count(), 2);

        // deleting an unconvertible object is a no-op
        store.ingest(&Change::Delete(Arc::new(Item(None))));
        assert_eq!(store.range(..).count(), 2);
    }
}
