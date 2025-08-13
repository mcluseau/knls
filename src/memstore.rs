use kube::runtime::watcher::Event;
use std::collections::{btree_map, BTreeMap};
use std::ops::RangeBounds;

pub struct Value<F, T> {
    value: Option<T>,
    map: fn(F) -> T,
}

impl<F, T> Value<F, T> {
    pub fn new(map: fn(F) -> T) -> Self {
        Self { value: None, map }
    }

    pub fn is_ready(&self) -> bool {
        self.value.is_some()
    }

    pub fn get(&self) -> Option<&T> {
        self.value.as_ref()
    }

    pub fn ingest(&mut self, event: Event<F>) {
        // single values are not sensitive to Init/InitDone: one received, they are ready
        use Event::*;
        match event {
            Init | Delete(_) => self.value = None,
            InitApply(v) | Apply(v) => self.value = Some((self.map)(v)),
            InitDone => {}
        }
    }
}

pub trait KeyValueFrom<V>: Sized {
    type Key: Ord;
    fn key_from(v: &V) -> Option<Self::Key>;
    fn value_from(v: V) -> Option<Self>;
}

pub struct Map<F, T: KeyValueFrom<F>> {
    map: BTreeMap<T::Key, T>,
    ready: bool,
}

impl<F, T: KeyValueFrom<F>> Map<F, T> {
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
            ready: false,
        }
    }

    pub fn is_ready(&self) -> bool {
        self.ready
    }

    pub fn get(&self, key: &T::Key) -> Option<&T> {
        self.map.get(key)
    }

    pub fn iter(&self) -> btree_map::Iter<'_, T::Key, T> {
        self.map.iter()
    }

    pub fn range<R: RangeBounds<T::Key>>(&self, bounds: R) -> btree_map::Range<'_, T::Key, T> {
        self.map.range(bounds)
    }

    pub fn ingest(&mut self, event: Event<F>) {
        use Event::*;
        match event {
            Init => {
                self.map.clear();
                self.ready = false
            }
            InitApply(v) => {
                if let (Some(key), Some(value)) = (T::key_from(&v), T::value_from(v)) {
                    self.map.insert(key, value);
                };
            }
            InitDone => self.ready = true,
            Apply(v) => {
                if let (Some(key), Some(value)) = (T::key_from(&v), T::value_from(v)) {
                    self.map.insert(key, value);
                }
            }
            Delete(v) => {
                if let Some(key) = T::key_from(&v) {
                    self.map.remove(&key);
                }
            }
        }
    }
}
