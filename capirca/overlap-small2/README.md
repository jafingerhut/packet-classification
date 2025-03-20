## Classifier Used

The classifier for `overlap-small2` has 2 rules, where the groups of
source and destination addresses have comments next to them showing
how many prefixes they contain:

```
term accept-web-services {
  source-address:: SRC_1        // 10 prefixes
  destination-address:: SRC_2   // 10 prefixes
  destination-port:: WEB_SERVICES  // 2 individual port numbers
  protocol:: tcp
  action:: accept
}

term accept-ssh {
  source-address:: SRC_3        // 5 prefixes
  destination-address:: SRC_4   // 5 prefixes
  destination-port:: SSH        // 1 individual port number
  protocol:: tcp
  action:: accept
}
```

## Capirca Generator Capabilities

The table below shows whether different Capirca generators allow
groups and overlap.

| Input file name | Generator | Output File | # rules in output | IP address groups preserved in output file? | Port groups preserved in output file? |
|-----------------|-----------|------------|-------------|-------------------|---------------------------------------------|---------------------------------------|
| k8singress.pol | Kubernetes NetworkPolicy | (none) [1] | N/A | N/A | N/A |
| k8segress.pol | Kubernetes NetworkPolicy | (none) [1] | N/A | N/A | N/A |
| sonic.pol | SONiC ACLs | [sonic.json](sonic.json) | 10x10x2 + 5x5x1 = 225 | no | no |
| cisco.pol | Cisco | [cisco.acl](cisco.acl) | 3 | yes | no, expanded |
| cisconx.pol | Cisco NX | [cisconx.nxacl](cisconx.nxacl) | 3 | yes | no, expanded |
| ciscoxr.pol | Cisco XR | [ciscoxr.xacl](ciscoxr.xacl) | 3 | yes | no, expanded |
| ciscoasa.pol | Cisco ASA | [ciscoasa.asa](ciscoasa.asa) | 10x10x2 + 5x5x1 = 225 | no | no |
| juniper.pol | Juniper | [juniper.jcl](juniper.jcl) | 2 | yes | yes |
| juniperevo.pol | Juniper EVO | [juniperevo.evojcl](juniperevo.evojcl) | 2 | yes | yes |
| msmpc.pol | Juniper MSMPC | [msmpc.msmpc](msmpc.msmpc) | 2 | yes | yes |
| srx.pol | Juniper SRX | [srx.srx](srx.srx) | 2 | yes | yes |


## Kubernetes policy restrictions

[1] The error message output by `aclgen` when attempting to generate
output for `k8singress.pol` is:

```
error encountered in rendering process:
Error generating target ACL for policies/pol/k8singress.pol:
Ingress rules cannot include "destination-address.
```

We believe this is because Kubernetes is a host-based implementation.
Thus it restricts you for ingress rules (network-to-host direction of
packet flow) to _not_ specify the destination address field.

The error message for `k8segress.pol` is:

```
error encountered in rendering process:
Error generating target ACL for policies/pol/k8segress.pol:
Egress rules cannot include "source-address".
```

Thus for egress rules (host-to-network direction of packet flow)
Kubernetes restricts you to _not_ specify the source address field.
