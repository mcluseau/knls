use core::ops::RangeBounds;
use kube::runtime::watcher::Event;
use std::collections::{BTreeMap, BTreeSet, HashMap, btree_map, hash_map::Entry};
use std::hash::Hash;

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
    pub fn ingest<T>(&mut self, event: &Event<T>)
    where
        for<'t> &'t T: Into<K>,
        for<'t> &'t T: Into<V>,
    {
        use Event::*;
        match event {
            Init => {
                self.ready = false;
            }
            InitDone => {
                self.ready = true;
            }
            InitApply(o) | Apply(o) => {
                self.map.insert(o.into(), o.into());
            }
            Delete(o) => {
                self.map.remove(&o.into());
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
    pub fn ingest(&mut self, event: &Event<T>) {
        use Event::*;
        match event {
            Init => {
                self.ready = false;
            }
            InitDone => {
                self.ready = true;
            }
            InitApply(o) | Apply(o) => {
                self.insert(o.into(), (self.get_values)(o));
            }
            Delete(o) => {
                self.remove(&o.into());
            }
        }
    }
}
