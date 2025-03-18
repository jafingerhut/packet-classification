## Example Classifier
The following table represents an example classifier with IPv4 source addresses, destination ports, and protocols.

| IPv4 Src | Dst Port | Protocol | Action |
|-------|-----|---------|
| 1.0.0.0/8 | {80, 443} | tcp | accept |
| 1.2.0.0/16 | 22 | tcp | accept |
| {1.2.3.0/24, 8.8.8.8/32} | 3306 | tcp | accept |

---

## Capirca Generator Capabilities
The table below shows whether different Capirca generators allow groups and overlap.

| Generator | Allows Groups | Allows Overlap |
|-------|-----|---------|
| Kubernetes NetworkPolicy | ✅ | ✅ |
| SONiC ACLs | ❌ | ✅ |
