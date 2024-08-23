use serde_json::json;

use memstore::KeyValueFrom;

use super::*;

#[test]
fn test_endpointslice() {
    let slice = json!({
        "apiVersion": "discovery.k8s.io/v1",
        "kind": "EndpointSlice",
        "addressType": "IPv4",
        "metadata": {
            "labels": {
                "app": "ui",
                "kubernetes.io/service-name": "ui"
            },
            "name": "ui-nmpw5",
            "namespace": "default",
            "ownerReferences": [
                {
                    "apiVersion": "v1",
                    "blockOwnerDeletion": true,
                    "controller": true,
                    "kind": "Service",
                    "name": "ui",
                }
            ]
        },
        "endpoints": [
            {
                "addresses": ["10.0.128.10"],
                "conditions": {
                    "ready": true,
                    "serving": true,
                    "terminating": false
                },
                "nodeName": "node1",
                "targetRef": {
                    "kind": "Pod",
                    "name": "ui-5bf9b57bc7-tvgqt",
                    "namespace": "default",
                },
                "zone": "z1"
            },
            {
                "addresses": ["10.0.128.4"], "conditions": { "ready": true, "serving": true, "terminating": false },
                "conditions": {
                    "ready": true,
                    "serving": true,
                    "terminating": false
                },
                "nodeName": "node2",
                "targetRef": {
                    "kind": "Pod",
                    "name": "ui-5bf9b57bc7-gdkcq",
                    "namespace": "default",
                    "uid": "ae0dabee-f2cc-4159-aa2b-90123009f839"
                },
                "zone": "z1"
            }
        ],
        "ports": [
            {
                "name": "",
                "port": 80,
                "protocol": "TCP"
            }
        ]
    });

    let slice: discovery::EndpointSlice = serde_json::from_value(slice).unwrap();

    assert_eq!(
        EndpointSlice::key_from(&slice),
        Some(keys::EndpointSlice {
            namespace: "default".into(),
            service_name: "ui".into(),
            name: "ui-nmpw5".into(),
        })
    );
}

/// a rather important and special endpointslice
#[test]
fn test_endpointslice_kubernetes() {
    let slice = json!({
        "apiVersion":"discovery.k8s.io/v1","kind":"EndpointSlice",
        "metadata":{
            "name":"kubernetes","namespace":"default",
            "labels":{"kubernetes.io/service-name":"kubernetes"},
        },
        "addressType":"IPv4",
        "endpoints":[
            {"addresses":["1.1.1.1"],"conditions":{"ready":true}},
            {"addresses":["2.2.2.2"],"conditions":{"ready":true}},
            {"addresses":["3.3.3.3"],"conditions":{"ready":true}}
        ],
        "ports":[{"name":"https","port":6443,"protocol":"TCP"}]
    });

    let slice: discovery::EndpointSlice = serde_json::from_value(slice).unwrap();

    assert_eq!(
        EndpointSlice::key_from(&slice),
        Some(keys::EndpointSlice {
            namespace: "default".into(),
            service_name: "kubernetes".into(),
            name: "kubernetes".into(),
        })
    );
}
