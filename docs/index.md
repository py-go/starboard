# {{ config.site_name }}

There are lots of security tools in the cloud native world, created by Aqua and by others, for identifying and informing
users about security issues in Kubernetes workloads and infrastructure components. However powerful and useful they
might be, they tend to sit alongside Kubernetes, with each new product requiring users to learn a separate set of
commands and installation steps in order to operate them and find critical security information.

Starboard attempts to integrate heterogeneous security tools by incorporating their outputs into Kubernetes CRDs
(Custom Resource Definitions) and from there, making security reports accessible through the Kubernetes API. This way
users can find and view the risks that relate to different resources in what we call a Kubernetes-native way.

Starboard provides:

- Automated vulnerability scanning for Kubernetes workloads.
- Automated configuration audits for Kubernetes resources with predefined rules or custom Open Policy Agent (OPA) policies.
- Automated infrastructures scanning and compliance checks with CIS Benchmarks published by the Center for Internet Security (CIS).
- [Custom Resource Definitions] and a [Go module] to work with and integrate a range of security scanners.

Starboard can be used:

- As a [Kubernetes operator] to automatically update security reports in response to workload and other changes on a
  Kubernetes cluster - for example, initiating a vulnerability scan when a new Pod is started or running CIS Benchmarks
  when a new Node is added.

## What's Next?

- Install the Starboard Operator with [kubectl](installation/kubectl.md) and follow the
  [Getting Started](getting-started.md) guide to see how vulnerability and configuration audit reports are
  generated automatically.

[Custom Resource Definitions]: ./crds/index.md
[Kubernetes operator]: overview.md
[Go module]: https://pkg.go.dev/github.com/danielpacak/kube-security-manager@{{ git.tag }}
[kubectl]: https://kubernetes.io/docs/reference/kubectl/
