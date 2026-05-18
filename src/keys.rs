use k8s_openapi::api::discovery::v1::EndpointSlice;
use std::cmp::Ordering;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Obj {
    ns: String,
    name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ByParent {
    Child { parent: Obj, name: String },
    Parent(Obj),
    ParentEnd(Obj),
}

impl Obj {
    pub fn new(ns: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            ns: ns.into(),
            name: name.into(),
        }
    }

    pub fn to_parent(&self) -> ByParent {
        ByParent::Parent(self.clone())
    }
    pub fn into_parent(self) -> ByParent {
        ByParent::Parent(self)
    }
}

impl fmt::Display for Obj {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.ns, self.name)
    }
}

impl ByParent {
    pub fn child(
        ns: impl Into<String>,
        parent: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self::Child {
            parent: Obj::new(ns, parent),
            name: name.into(),
        }
    }

    pub fn start(self) -> Self {
        match self {
            Self::Child { parent, .. } => Self::Parent(parent),
            Self::Parent(_) => self,
            Self::ParentEnd(o) => Self::Parent(o),
        }
    }

    pub fn end(self) -> Self {
        match self {
            Self::Child { parent, .. } => Self::ParentEnd(parent),
            Self::Parent(o) => Self::ParentEnd(o),
            Self::ParentEnd(_) => self,
        }
    }
}

impl Ord for ByParent {
    fn cmp(&self, o: &Self) -> Ordering {
        use ByParent::*;
        match self {
            Child {
                parent: ap,
                name: an,
            } => match o {
                Child {
                    parent: bp,
                    name: bn,
                } => ap.cmp(bp).then_with(|| an.cmp(bn)),
                Parent(bp) => ap.cmp(bp).then(Ordering::Greater), // parent < child*
                ParentEnd(bp) => ap.cmp(bp).then(Ordering::Less), // child* < parent end
            },
            Parent(ap) => match o {
                Child {
                    parent: bp,
                    name: _,
                } => ap.cmp(bp).then(Ordering::Less), // parent* < child
                Parent(bp) => ap.cmp(bp),
                ParentEnd(bp) => ap.cmp(bp).then(Ordering::Less), // parent* < parent end
            },
            ParentEnd(ap) => match o {
                Child {
                    parent: bp,
                    name: _,
                } => ap.cmp(bp).then(Ordering::Greater), // child < parent end*
                Parent(bp) => ap.cmp(bp).then(Ordering::Greater), // parent < parent end*
                ParentEnd(bp) => ap.cmp(bp),
            },
        }
    }
}

impl PartialOrd for ByParent {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

impl<T> From<&T> for Obj
where
    T: kube::Resource<Scope = k8s_openapi::NamespaceResourceScope>,
{
    fn from(v: &T) -> Self {
        let meta = v.meta();
        Self {
            ns: (meta.namespace)
                .clone()
                .expect("namespaced resource should have a namespace"),
            name: (meta.name)
                .clone()
                .expect("namespaced resource should have a name"),
        }
    }
}

pub trait WithParent {
    fn parent(&self) -> String;
}

impl<T> From<&T> for ByParent
where
    T: kube::Resource<Scope = k8s_openapi::NamespaceResourceScope>,
    T: WithParent,
{
    fn from(v: &T) -> Self {
        let k = Obj::from(v);
        Self::Child {
            parent: Obj {
                ns: k.ns,
                name: v.parent(),
            },
            name: k.name,
        }
    }
}

impl WithParent for EndpointSlice {
    fn parent(&self) -> String {
        (self.metadata.owner_references.iter().flatten())
            .find_map(|o| (o.kind == "Service").then_some(o.name.clone()))
            .or_else(|| {
                (self.metadata.labels.as_ref())
                    .and_then(|l| l.get("kubernetes.io/service-name").cloned())
            })
            .unwrap_or_else(|| {
                panic!(
                    "EndpointSlice {:?}/{:?} must be owned by a Service",
                    self.metadata.namespace.as_deref().unwrap_or("?"),
                    self.metadata.name.as_deref().unwrap_or("?")
                )
            })
    }
}

#[test]
fn test_obj() {
    use std::collections::BTreeMap as Map;

    fn k(ns: &str, name: &str) -> Obj {
        Obj::new(ns, name)
    }

    let map = Map::from_iter([
        (k("a", "a"), 1),
        (k("a", "b"), 2),
        (k("b", "a"), 3),
        (k("b", "b"), 4),
        (k("c", "a"), 5),
        (k("c", "b"), 6),
    ]);

    assert_eq!(
        vec![1, 2, 3, 4, 5, 6],
        map.values().cloned().collect::<Vec<_>>()
    );

    assert_eq!(
        vec![2, 3, 4],
        map.range(k("a", "b")..k("c", "a"))
            .map(|(_, v)| *v)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        vec![2, 3, 4, 5],
        map.range(k("a", "b")..=k("c", "a"))
            .map(|(_, v)| *v)
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_by_parent() {
    use std::collections::BTreeMap as Map;

    fn k(ns: &str, parent: &str, name: &str) -> ByParent {
        ByParent::Child {
            parent: Obj {
                ns: ns.into(),
                name: parent.into(),
            },
            name: name.into(),
        }
    }
    fn p(ns: &str, parent: &str) -> ByParent {
        Obj::new(ns, parent).into_parent()
    }

    let map = Map::from_iter([
        (k("a", "a", "a-1"), 1),
        (k("a", "b", "b-1"), 2),
        (k("b", "a", "a-1"), 3),
        (k("b", "b", "b-1"), 4),
        (k("b", "b", "b-2"), 5),
        (k("b", "c", "c-1"), 6),
        (k("c", "a", "a-1"), 7),
        (k("c", "b", "b-1"), 8),
    ]);

    assert_eq!(
        vec![1, 2, 3, 4, 5, 6, 7, 8],
        map.values().cloned().collect::<Vec<_>>()
    );

    assert_eq!(
        vec![2, 3, 4],
        map.range(k("a", "b", "b-1")..k("b", "b", "b-2"))
            .map(|(_, v)| *v)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        vec![2, 3, 4, 5],
        map.range(k("a", "b", "b-1")..=k("b", "b", "b-2"))
            .map(|(_, v)| *v)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        vec![4, 5],
        map.range(p("b", "b")..p("b", "b").end())
            .map(|(_, v)| *v)
            .collect::<Vec<_>>()
    );
}
