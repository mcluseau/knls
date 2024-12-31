# Kubernetes Node-Local Services

Watch the Kubernetes API server to provide node-specific services:
- kube-proxy service using nftables
- authoritative DNS
- pod connectivity through wireguard

## Install using helm

from this repository:

    helm -n kube-system install knls ./helm

