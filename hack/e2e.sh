#!/usr/bin/env bash
#
# Run the Kubernetes e2e suite (Ginkgo) from the conformance image, against the
# cluster currently selected by kubeconfig.
#
# knls is expected to already be deployed there as the kube-proxy replacement:
# this script only runs tests, it provisions nothing. By default it runs the
# networking tests (`[sig-network]`), which is where a kube-proxy replacement is
# exercised.
#
# The Ginkgo CLI and e2e.test binary come from
# `registry.k8s.io/conformance:<version>`, so no local toolchain is needed and
# the test version matches the cluster.
#
# Usage:
#   hack/e2e.sh
#   K8S_VERSION=v1.31.0 hack/e2e.sh
#   FOCUS='\[Conformance\]' hack/e2e.sh          # full conformance suite
#   SKIP='LoadBalancer' NODES=4 hack/e2e.sh
#   hack/e2e.sh --ginkgo.label-filter='!disruptive'   # extra e2e.test flags
#
# Environment:
#   K8S_VERSION  Kubernetes version to test, e.g. v1.31.0
#                (default: the server version reported by the cluster)
#   KUBECONFIG   kubeconfig to test against (default: ~/.kube/config)
#   FOCUS        Ginkgo focus regex (default: \[sig-network\])
#   SKIP         extra Ginkgo skip regex, added to the built-in list below of
#                specs that cannot pass against a knls cluster
#   NODES        Ginkgo parallel nodes (default: 1)
#   ARTIFACTS    report directory (default: $PWD/tmp/e2e-results)
#   IMAGE        conformance image (default: registry.k8s.io/conformance:$K8S_VERSION)
#   E2E_ARGS     extra e2e.test args, space-separated (appended after `--`)
#   docker_args  extra `docker run` flags, space-separated (e.g. --net=host)

set -euo pipefail

kubeconfig=${KUBECONFIG:-${HOME}/.kube/config}
focus=${FOCUS:-'\[sig-network\]'}
# Specs that cannot pass against a knls cluster (or are marked not applicable
# upstream) are always skipped; a caller-provided SKIP adds more:
#   - DualStack / Disruptive / LoadBalancer: single-stack, disruptive, no cloud
#     provider
#   - DNS `configMap nameserver`: they need a kube-dns/CoreDNS pod to edit,
#     which knls replaces
#   - `Networking-IPv6`: needs an IPv6/dual-stack cluster
#   - `RelaxedServiceNameValidation`: alpha feature gate, disabled
default_skip='DualStack|Disruptive|LoadBalancer|DNS configMap nameserver|Networking-IPv6|RelaxedServiceNameValidation'
skip="${SKIP:+${SKIP}|}${default_skip}"
nodes=${NODES:-1}
artifacts=${ARTIFACTS:-${PWD}/tmp/e2e-results}

# Extra `docker run` flags and extra e2e.test args (word-split on purpose),
# defaulted so `set -u` is happy when they are unset.
: "${docker_args:=}"
: "${E2E_ARGS:=}"

die() {
	echo "e2e: $*" >&2
	exit 1
}

[[ -f "$kubeconfig" ]] || die "no kubeconfig at $kubeconfig (set KUBECONFIG)"
command -v docker >/dev/null || die "docker is not installed"

# The version to test, used both to pick the image and to match the cluster.
k8s_version=${K8S_VERSION:-}
if [[ -z "$k8s_version" ]] && command -v kubectl >/dev/null; then
	# Newer kubectl only accepts yaml/json for `version`, so read the raw
	# /version object instead: a flat JSON body with a single gitVersion field.
	k8s_version=$(kubectl --kubeconfig="$kubeconfig" get --raw /version 2>/dev/null |
		jq -r .gitVersion)
fi
[[ -n "$k8s_version" ]] || die "could not detect the cluster version; set K8S_VERSION"
image=${IMAGE:-registry.k8s.io/conformance:${k8s_version}}

mkdir -p "$artifacts"

# Ginkgo CLI flags. Ginkgo v2's default timeout is 1h; e2e runs need more, so
# upstream's hack/ginkgo-e2e.sh hardcodes 24h.
ginkgo_args=(
	"--timeout=24h"
	#"--no-color"
	"--poll-progress-after=60m"
	"--poll-progress-interval=5m"
    #"--dry-run"
    #"-v"
)
[[ "$nodes" -gt 1 ]] && ginkgo_args+=("--nodes=$nodes")
[[ -n "$focus" ]] && ginkgo_args+=("--focus=$focus")
[[ -n "$skip" ]] && ginkgo_args+=("--skip=$skip")

# e2e.test flags, after the `--` separator. `skeleton` is the fallback provider
# for a cluster we did not provision; reports land in the mounted /tmp/results.
e2e_args=(
    --kubeconfig=/cfg/e2e-config
	--provider=skeleton
	--disable-log-dump
	--report-dir=/tmp/results
	--report-complete-ginkgo
	--report-complete-junit
)

echo "e2e: image=$image"
echo "e2e: kubeconfig=.kube/config"
echo "e2e: focus=${focus:-<all>} skip=${skip:-<none>} nodes=$nodes"
echo "e2e: reports in $artifacts"

# Override the image entrypoint (its default `kubeconformance` wrapper) so the
# Ginkgo CLI is driven directly: `ginkgo [flags] e2e.test -- [suite flags]`.
exec docker run --rm -w /root \
	-v "$PWD/.kube:/cfg:ro" -w /cfg \
	-v "$artifacts":/tmp/results \
    $docker_args \
	--entrypoint /usr/local/bin/ginkgo \
	"$image" \
	"${ginkgo_args[@]}" \
	/usr/local/bin/e2e.test -- \
	"${e2e_args[@]}" ${E2E_ARGS} \
	"$@"
