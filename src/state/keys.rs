use k8s_openapi::apimachinery::pkg::apis::meta::v1 as meta;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub struct Object {
    pub namespace: String,
    pub name: String,
}
impl TryFrom<&meta::ObjectMeta> for Object {
    type Error = &'static str;
    fn try_from(metadata: &meta::ObjectMeta) -> Result<Self, Self::Error> {
        Ok(Self {
            namespace: metadata.namespace.clone().ok_or("no namespace")?,
            name: metadata.name.clone().ok_or("no name")?,
        })
    }
}
impl std::fmt::Display for Object {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}/{}", self.namespace, self.name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub struct EndpointSlice {
    pub namespace: String,
    pub service_name: String,
    pub name: String,
}
impl EndpointSlice {
    pub fn is_service(&self, key: &Object) -> bool {
        self.namespace == key.namespace && self.service_name == key.name
    }
}
