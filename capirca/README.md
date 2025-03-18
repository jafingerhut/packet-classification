## Example Classifier Used
The following table represents an example classifier with IPv4 source addresses, destination ports, and protocols.

| IPv4 Src | Dst Port | Protocol | Action |
|-------|-----|---------|------|
| 1.0.0.0/8 | {80, 443} | tcp | accept |
| 1.2.0.0/16 | 22 | tcp | accept |
| {1.2.3.0/24, 8.8.8.8/32} | 3306 | tcp | accept |

---

## Capirca Generator Capabilities
The table below shows whether different Capirca generators allow groups and overlap.

| Generator | File | Allows Groups | Allows Overlap |
|-------|-----|------|---------|
| Kubernetes NetworkPolicy | [k8s.yml](https://github.com/rfchang/packet-classification/blob/main/capirca/k8s.yml) | ✅ | ✅ |
| SONiC ACLs | [sonic.json](https://github.com/rfchang/packet-classification/blob/main/capirca/sonic.json) | ❌ | ✅ |
| Cisco | [cisco.acl](https://github.com/rfchang/packet-classification/blob/main/capirca/cisco.acl) | ✅ | ✅ |
| Cisco NX | [cisconx.nxacl](https://github.com/rfchang/packet-classification/blob/main/capirca/cisconx.nxacl) | ✅ | ✅ |
| Cisco XR | [ciscoxr.xacl](https://github.com/rfchang/packet-classification/blob/main/capirca/ciscoxr.xacl) | ✅ | ✅ |
| Cisco ASA | [ciscoasa.asa](https://github.com/rfchang/packet-classification/blob/main/capirca/ciscoasa.asa) | ❌ | ✅ |
| Juniper | [juniper.jcl](https://github.com/rfchang/packet-classification/blob/main/capirca/juniper.jcl) | ✅ | ✅ |
| Juniper EVO | [juniperevo.evojcl](https://github.com/rfchang/packet-classification/blob/main/capirca/juniperevo.evojcl) | ✅ | ✅ |
| Juniper MSMPC | [msmpc.msmpc](https://github.com/rfchang/packet-classification/blob/main/capirca/msmpc.msmpc) | ✅ | ✅ |
| Juniper SRX | [srx.srx](https://github.com/rfchang/packet-classification/blob/main/capirca/srx.srx) | ✅ | ✅ |
