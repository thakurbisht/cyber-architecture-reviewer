# Store Network Refresh — SD-WAN, Store LAN and Remote Access Design

Brightwell Home & Garden, Infrastructure & Networks. Version 2.0, for design authority approval.

## 1. Purpose and Scope

Brightwell operates 300 stores in the UK and Ireland, a head office in Leicester and two data centres (DC1 Coventry, DC2 Milton Keynes). The MPLS contract ends in Q3 next year. This design replaces the MPLS WAN and branch routers with cloud-managed SD-WAN firewall appliances, introduces local internet breakout, refreshes store switching and Wi-Fi, and replaces the remote-access VPN concentrators.

In scope: WAN and overlay, store LAN segmentation, wireless, remote access, third-party support access, network management and logging. Out of scope: the POS application, the data centre core network and the e-commerce platform.

## 2. Design Summary

Figure 1 shows the target topology. Each store has one SD-WAN edge appliance (two in the 40 largest stores), two access switches and four to ten access points. The edges and access points are configured and monitored from the vendor's cloud controller. Store switches are managed from the network management system (NMS) in DC1.

| Element | Standard |
|---|---|
| SD-WAN edge | Cloud-managed firewall appliance, HA pair in large stores |
| WAN circuits | Business broadband primary, 4G LTE backup |
| Switching | Two 48-port PoE switches per store |
| Wireless | Cloud-managed Wi-Fi 6 access points |
| Remote access | SSL VPN on DC1 firewall pair |

## 3. WAN and Internet Breakout

Each store has a single business broadband circuit (80–500 Mbps) and a 4G LTE backup; MPLS is removed entirely, and store traffic to the data centres crosses the public internet. The SD-WAN edges are configured and monitored entirely from the vendor's cloud controller over the internet.

Traffic is steered by application policy as shown in the table below and in Figure 2.

| Traffic class | Path |
|---|---|
| POS payment authorisation and journals | Overlay to DC1 (DC2 standby) |
| ERP, HR and stock systems | Overlay to DC1 |
| Microsoft 365 | Local breakout |
| General web browsing from back-office PCs | Local breakout |
| Guest Wi-Fi | Local breakout |

General internet browsing from back-office PCs breaks out locally at the store edge to reduce overlay bandwidth and improve SaaS performance.

## 4. Store LAN Design

| VLAN | Name | Devices |
|---|---|---|
| 10 | Management | Switch management interfaces |
| 20 | POS | Tills, PIN pads, in-store POS server |
| 30 | Back office | Manager PCs, printers, label printers |
| 40 | Staff devices | Handheld stock scanners, staff tablets |
| 50 | Building systems | CCTV recorders, HVAC controllers, door access |
| 90 | Guest | Guest Wi-Fi clients |

The in-store POS server aggregates till transactions, including card authorisation data, and forwards them to the payment switch in DC1.

Switch access ports are assigned to VLANs statically from the store build template, so that replacement devices can be connected without network team involvement. The store edge is the default gateway for every VLAN. VLANs 20–50 form the store's internal firewall zone, and the store policy permits all traffic between VLANs within the internal zone so that back-office PCs and scanners can reach the POS server and printers.

## 5. Wireless

Access points broadcast two SSIDs. Brightwell-Staff uses WPA2-Enterprise with EAP-TLS; corporate handhelds and tablets authenticate with device certificates issued by the corporate PKI and are placed in VLAN 40. The guest SSID, Brightwell-Guest, is an open network with a captive portal for terms acceptance, available to customers in every store.

## 6. Remote Access

### 6.1 Staff and Supplier VPN

Remote-access VPN for head-office staff, area managers and IT (about 2,500 users) terminates on the DC1 firewall pair as SSL VPN on TCP 443. Users authenticate with their Active Directory username and password, which the firewall checks against the NPS RADIUS servers.

Third-party suppliers, including the network managed service provider (MSP) and two application vendors, are issued VPN accounts in a dedicated Active Directory OU. All VPN clients, staff and suppliers alike, receive addresses from the pool 10.200.0.0/16. The VPN uses a full tunnel, so remote users' internet traffic passes through the DC1 secure web gateway.

### 6.2 POS Vendor Support

Tillcraft, the POS software vendor, provides third-line support for tills and POS servers. On each store edge, TCP 5900 on the broadband public IP address is forwarded to the POS server in VLAN 20 from any source address, so that Tillcraft engineers can connect with VNC.

## 7. Security Controls

All store-to-data-centre traffic, including traffic over the LTE backup, is carried in the SD-WAN overlay, which uses IPsec tunnels (IKEv2, AES-256-GCM) authenticated with device certificates issued by the controller.

The guest zone (VLAN 90) has a deny-all policy towards the internal zone, the management VLAN and the overlay; guest traffic can only egress through local breakout, and client isolation is enabled on the guest SSID.

Web filtering, TLS inspection and malware sandboxing for corporate users are provided by the secure web gateway proxy cluster in DC1. Store edges are licensed for stateful firewalling and SD-WAN only.

## 8. Network Management

### 8.1 Cloud Controller

Edges and access points hold an outbound TLS session to the cloud controller for configuration and telemetry; they accept no inbound management connections on their WAN interfaces, and the local status page is disabled.

The cloud controller dashboard is administered with local dashboard accounts. The MSP's network operations centre uses a single shared account, noc@brightwell-msp.example, with Organisation Administrator rights over all 300 stores. SAML federation with the corporate identity provider is planned for a later phase.

### 8.2 Switches

Store switches are managed over SSHv2, with authentication and command authorisation through TACACS+ servers in DC1 and DC2. If both TACACS+ servers are unreachable, switches fall back to the local account netadmin, whose password is set in the standard configuration template and is identical on all store switches.

The NMS in DC1 polls store switches using SNMP v2c with a read-write community string common to all stores, which it also uses to push VLAN and port changes.

Switch management interfaces in VLAN 10 accept SSH and SNMP from the NMS subnet 10.10.5.0/24 and from the VPN pool 10.200.0.0/16, so that network engineers can work remotely.

## 9. Logging and Monitoring

Store edge firewall event and traffic logs are held in the cloud controller, which retains them for seven days. The corporate SIEM collects Active Directory, VPN, DC firewall and secure web gateway logs and retains them for 12 months. The MSP monitors circuit and device health from the controller and raises incidents in the service desk tool.

## 10. Resilience

Large stores have an HA pair of edges; all stores fail over to 4G LTE within 30 seconds if broadband is lost. If the overlay to DC1 is unavailable, payment traffic fails over to DC2. Edge configurations are held by the cloud controller and are re-applied automatically when a replacement appliance is registered.
