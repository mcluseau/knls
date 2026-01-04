use std::collections::{BTreeMap as Map, btree_map};
use std::mem;

#[derive(Debug)]
pub struct Tracker<K: Ord, T: Eq> {
    values: Map<K, Item<T>>,
}
impl<K: Ord + Clone, T: Eq> Tracker<K, T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear(&mut self) {
        self.values.clear();
    }

    pub fn check(&mut self, key: K, value: &T) -> Option<Change<'_, K, T>> {
        // get current value and mark it as seen
        let entry = self.values.entry(key).and_modify(|e| e.touch());

        use btree_map::Entry;
        let kind = match entry {
            Entry::Vacant(_) => Kind::Created,
            Entry::Occupied(ref e) => {
                if Some(value) == e.get().prev.as_ref() {
                    return None;
                } else {
                    Kind::Modified
                }
            }
        };

        Some(Change { kind, entry })
    }

    pub fn is_deleted(&self, key: &K) -> bool {
        let Some(v) = self.values.get(key) else {
            return true; // not in the set
        };
        matches!(v.state, State::Unseen)
    }

    pub fn deleted(&self) -> impl Iterator<Item = &K> {
        self.values.iter().filter_map(|(k, v)| match v.state {
            State::Unseen => Some(k),
            _ => None,
        })
    }

    pub fn current_keys(&self) -> impl Iterator<Item = &K> {
        self.values.iter().filter_map(|(k, v)| match v.state {
            State::Unseen => None,
            State::Seen | State::Modified(_) => Some(k),
        })
    }

    pub fn update_done(&mut self) {
        self.values.retain(|_, v| {
            let prev_state = mem::replace(&mut v.state, State::Unseen);
            match prev_state {
                State::Unseen => false,
                State::Seen => true,
                State::Modified(new_value) => {
                    v.prev = Some(new_value);
                    true
                }
            }
        });
    }

    pub fn update_failed(&mut self) {
        self.values.retain(|_, v| {
            v.state = State::Unseen;
            v.prev.is_some()
        });
    }
}

impl<K: Ord + Clone, T: Eq> Default for Tracker<K, T> {
    fn default() -> Self {
        Self { values: Map::new() }
    }
}

#[derive(Debug)]
struct Item<T> {
    prev: Option<T>,
    state: State<T>,
}
impl<T> Item<T> {
    fn touch(&mut self) {
        use State::*;
        if let Unseen = self.state {
            self.state = Seen;
        }
    }
}

type Entry<'t, K, T> = btree_map::Entry<'t, K, Item<T>>;

#[derive(Debug)]
enum State<T> {
    Unseen,
    Seen,
    Modified(T),
}

pub struct Change<'a, K: Ord, T> {
    pub kind: Kind,
    entry: Entry<'a, K, T>,
}
impl<'a, K: Ord, T> Change<'a, K, T> {
    pub fn key(&self) -> &K {
        self.entry.key()
    }

    pub fn set(self, value: T) {
        use btree_map::Entry;
        let new_state = State::Modified(value);
        match self.entry {
            Entry::Vacant(e) => {
                e.insert(Item {
                    prev: None,
                    state: new_state,
                });
            }
            Entry::Occupied(mut e) => {
                e.get_mut().state = new_state;
            }
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum Kind {
    Created,
    Modified,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_crud() {
        let mut items = Tracker::<&str, u8>::new();

        // new value
        let change = items.check("key", &0).unwrap();
        assert_eq!(change.kind, Kind::Created);
        change.set(0);
        items.update_done();

        // update with the same value
        assert!(items.check("key", &0).is_none());
        items.update_done();

        // update with a different value
        let change = items.check("key", &1).unwrap();
        assert_eq!(change.kind, Kind::Modified);
        change.set(1);
        items.update_done();

        // "key" no set, it should be considered as deleted
        assert_eq!(items.deleted().collect::<Vec<_>>(), vec![&"key"]);
        items.update_done();
    }
}
