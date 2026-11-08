# Kubernetes Cluster Upgrades

Owner: Container Platform

## Version policy

Control planes are upgraded one minor version at a time. Worker nodes may lag
the control plane by at most two minor versions. The platform team maintains
a tested upgrade path for every supported version.

## Node draining

Draining uses pod disruption budgets and a maximum of 10% of nodes per zone.
Stateful workloads are migrated explicitly by their owning teams before the
maintenance window.

## Add-on compatibility

Ingress, CNI, and CSI versions must be verified against the target Kubernetes
release. Cluster autoscaler and metrics-server are upgraded before workloads.

## Rollback

Control-plane upgrades are not rolled back in place. A failed upgrade is
recovered by rebuilding from the last validated cluster snapshot and shifting
traffic back through the edge gateway.
