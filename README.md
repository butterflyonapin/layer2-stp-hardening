
# Layer 2/3 Infrastructure Exploitation: STP Hijacking & Rogue Router Containment

Technical analysis of Spanning Tree Protocol (STP) mechanics, BPDU injection vulnerabilities, and rogue router insertions in Enterprise LANs, demonstrating Root Bridge hijacking, routing poison attacks, and enforcement of Boundary Defenses via Next-Generation Firewalls (NGFW) and Layer 3 Switches.

---

## What is Spanning Tree Protocol (STP) and How Does It Work?

Spanning Tree Protocol (IEEE 802.1D / 802.1w) is a Layer 2 network protocol designed to prevent switching loops in networks with redundant physical paths.

### The Problem: Layer 2 Switching Loops

Unlike Layer 3 IP packets, Layer 2 Ethernet frames lack a Time to Live (TTL) field. If redundant paths exist between switches without STP, frames (especially broadcast and multicast) circulate endlessly. This creates **Broadcast Storms** and MAC address table instability, collapsing the entire network within seconds.

### How STP Works (Election & Port States)

STP dynamically creates a loop-free logical topology by disabling redundant links while keeping them ready for failover.

1. **Root Bridge Election:** All switches broadcast Bridge Protocol Data Units (BPDUs) to elect a single "Root Bridge" for the topology. The switch with the lowest **Bridge Identifier (BID)** wins:

$$\text{BID} = \text{Bridge Priority (2 bytes)} + \text{System ID Ext} + \text{MAC Address (6 bytes)}$$

2. **Root Path Cost Calculation:** Each non-root switch calculates the shortest path cost back to the Root Bridge.
3. **Port Role Assignment:**
* **Root Port (RP):** The interface on a switch with the best path to the Root Bridge.
* **Designated Port (DP):** The interface on a network segment with the best path to the Root Bridge (transmits traffic).
* **Non-Designated Port (Blocking):** Redundant interfaces placed in a discarding state to break physical loops.



---

## Attack Vectors: Layer 2 & Layer 3 Exploitation

By default, unhardened enterprise access ports suffer from implicit trust. An attacker or unauthorized user plugging a rogue device (such as a router or unmanaged switch) into an access port can disrupt the infrastructure via two vectors:

### Vector 1: Layer 2 Root Bridge Hijacking

An attacker injects superior BPDUs with a lower Bridge Priority (`0`). The switches accept the claim, trigger a topology reconvergence, and elect the attacker's device as the Root Bridge. Inter-VLAN traffic is rerouted toward the edge port, creating a Denial of Service (DoS) or Man-In-The-Middle (MITM) condition.

```yaml
"                                [ Enterprise Firewall / NGFW ]"
"                                               │"
"                                 [ Core Switch / L3 Switch ]"
"                                               │"
"                                  [ Edge Access Switch ]"
"                                               │ (Access Port - Unprotected)"
"                                               ▼"
" [ Attacker / Rogue Router ] (Injects BPDUs & Rogue DHCP/Routes) <-- Injection Point"
```

### Vector 2: Layer 3 Rogue Router Insertion

When an unauthorized router is attached to an access port:

* It issues **Rogue DHCP Offers**, assigning clients incorrect IP configurations and setting itself as the Default Gateway.
* If dynamic routing (OSPF/EIGRP/BGP) is enabled on edge ports, it advertises a metric `0` default route (`0.0.0.0/0`), hijacking outbound traffic intended for the enterprise firewall.

---

## Infrastructure & Firewall Boundary Hardening

To ensure that attaching an unauthorized router or switch cannot compromise the network, zero-trust boundary defenses must be enforced across Layer 2 and Layer 3.

### 1. Firewall & Core Boundary Isolation (Layer 3 Defense)

#### A. Passive Interfaces & Dynamic Routing Filtering

Disable dynamic routing neighbor formation on all client-facing ports to prevent rogue routers from injecting routes.

```cisco
! Disable dynamic routing neighbors on all non-infrastructure ports
Core-Switch(config)# router ospf 1
Core-Switch(config-router)# passive-interface default
Core-Switch(config-router)# no passive-interface GigabitEthernet0/1  ! (Only explicit link to Firewall)

```

#### B. DHCP Snooping & IP Source Guard

Enforce DHCP Snooping to block rogue DHCP servers and unauthorized gateways on access ports.

```cisco
! Enable DHCP Snooping globally
Access-Switch(config)# ip dhcp snooping
Access-Switch(config)# ip dhcp snooping vlan 10

! Trust ONLY uplink interfaces connected to authorized DHCP servers/Firewalls
Access-Switch(config)# interface GigabitEthernet0/1
Access-Switch(config-if)# ip dhcp snooping trust

! Client interfaces drop all DHCP Server (OFFER/ACK) packets by default

```

---

### 2. Layer 2 Boundary Protection (BPDU Guard & Priority Assignment)

#### A. Hardcode Core Priorities

Prevent edge devices from winning Root Bridge elections by lowering Core switch priorities.

```cisco
! Core Primary
SW-Core-01(config)# spanning-tree vlan 10 priority 4096

! Core Backup
SW-Core-02(config)# spanning-tree vlan 10 priority 8192

```

#### B. Enforce BPDU Guard on Edge Interfaces

Shutdown any access port instantly if it detects incoming BPDUs from a switch or router.

```cisco
SW-Access-01(config)# interface range fastEthernet 0/1 - 24
SW-Access-01(config-if-range)# switchport mode access
SW-Access-01(config-if-range)# spanning-tree portfast
SW-Access-01(config-if-range)# spanning-tree bpduguard enable

```

---

## Forensics & Triage Commands

```cisco
# Inspect interfaces disabled due to unauthorized BPDU ingestion
SW-Access-01# show interfaces status err-disabled

# Verify DHCP Snooping binding database and blocked rogue servers
SW-Access-01# show ip dhcp snooping binding

# Verify current STP Root Bridge parameters per VLAN
SW-Access-01# show spanning-tree vlan 10 detail

```

---

## Repository Contents

```text
.
├── README.md
└── configs/
    ├── core_switch.cfg
    ├── access_switch.cfg
    └── firewall_policy.cfg

```
