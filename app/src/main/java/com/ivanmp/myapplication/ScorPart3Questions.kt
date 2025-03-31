package com.ivanmp.myapplication

/**
 * This file contains the SCOR PART 3 questions.
 */
object ScorPart3Questions {
    
    /**
     * Returns a list of SCOR PART 3 questions.
     */
    fun getQuestions(): List<Question> {
        return listOf(
            Question.MultipleChoice(
                "What is a functional difference between a Cisco ASA and a Cisco IOS router with Zone-based policy firewall?",
                listOf(
                    "A. The Cisco ASA denies all traffic by default whereas the Cisco IOS router with Zone-Based Policy Firewall starts out by allowing all traffic, even on untrusted interfaces.",
                    "B. The Cisco IOS router with Zone-Based Policy Firewall can be configured for high availability, whereas the Cisco ASA cannot",
                    "C. The Cisco IOS router with Zone-Based Policy Firewall denies all traffic by default, whereas the Cisco ASA starts out by allowing all traffic until rules are added",
                    "D. The Cisco ASA can be configured for high availability whereas the Cisco IOS router with Zone-Based Policy Firewall cannot"
                ),
                setOf("A"),
                """Both Cisco ASA and Cisco IOS router with Zone-based policy firewall support High Availability (HA).
Zone-Based Policy Firewall drops traffic if it is from a different zone by default. So we cannot say if Cisco IOS router with Zone-Based Policy Firewall allows or denies traffic by default.
Cisco ASA drops all traffic by default.
But we found a similar answer to this question:
The ASA denies all traffic by default, while the IOS router starts out by allowing all traffic, even on your untrusted interfaces.
Reference: https://www.plixer.com/blog/cisco-zone-based-firewall-reporting/
So maybe this question wanted to say Cisco IOS router allows all traffic by default (before implementing Zone-Based Policy Firewall).""",
                "https://www.plixer.com/blog/cisco-zone-based-firewall-reporting/",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "What is a benefit of performing device compliance?",
                listOf(
                    "A. verification of the latest OS patches",
                    "B. device classification and authorization",
                    "C. providing multi-factor authentication",
                    "D. providing attribute-driven policies"
                ),
                setOf("A"),
                "",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "Which cloud model is a collaborative effort where infrastructure is shared and jointly accessed by several organizations from a specific group?",
                listOf(
                    "A. hybrid",
                    "B. community",
                    "C. private",
                    "D. public"
                ),
                setOf("B"),
                """Community Cloud allows system and services to be accessible by group of organizations. It shares the infrastructure between several organizations from a specific community. It may be managed internally by organizations or by the third-party.""",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "Which cryptographic process provides origin confidentiality, integrity, and origin authentication for packets?",
                listOf(
                    "A. IKEv1",
                    "B. AH",
                    "C. ESP",
                    "D. IKEv2"
                ),
                setOf("C"),
                "",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "An organization wants to secure users, data, and applications in the cloud. The solution must be API-based and operate as a cloud-native CASB. Which solution must be used for this implementation?",
                listOf(
                    "A. Cisco Cloudlock",
                    "B. Cisco Cloud Email Security",
                    "C. Cisco Firepower Next-Generation Firewall",
                    "D. Cisco Umbrella"
                ),
                setOf("A"),
                """Cisco Cloudlock: Secure your cloud users, data, and applications with the cloud-native Cloud Access Security Broker (CASB) and cloud cybersecurity platform.""",
                "https://www.cisco.com/c/dam/en/us/products/collateral/security/cloud-web-security/at-a-glance-c45-738565.pdf",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "What are two Trojan malware attacks? (Choose two)",
                listOf(
                    "A. frontdoor",
                    "B. rootkit",
                    "C. smurf",
                    "D. backdoor",
                    "E. sync"
                ),
                setOf("B", "D"),
                "",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "What is the role of Cisco Umbrella Roaming when it is installed on an endpoint?",
                listOf(
                    "A. to protect the endpoint against malicious file transfers",
                    "B. to ensure that assets are secure from malicious links on and off the corporate network",
                    "C. to establish secure VPN connectivity to the corporate network",
                    "D. to enforce posture compliance and mandatory software"
                ),
                setOf("B"),
                """Umbrella Roaming is a cloud-delivered security service for Cisco's next-generation firewall. It protects your employees even when they are off the VPN.""",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "What is a capability of Cisco ASA Netflow?",
                listOf(
                    "A. It filters NSEL events based on traffic.",
                    "B. It generates NSEL events even if the MPF is not configured.",
                    "C. It logs all event types only to the same collector.",
                    "D. It sends NetFlow data records from active and standby ASAs in an active standby failover pair."
                ),
                setOf("A"),
                "",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "Which component of Cisco umbrella architecture increases reliability of the service?",
                listOf(
                    "A. Anycast IP",
                    "B. AMP Threat grid",
                    "C. Cisco Talos",
                    "D. BGP route reflector"
                ),
                setOf("A"),
                """Cisco Umbrella Uses Anycast IP routing in order to provide reliability of the recursive DNS service.""",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "What is the benefit of integrating Cisco ISE with a MDM solution?",
                listOf(
                    "A. It provides compliance checks for access to the network",
                    "B. It provides the ability to update other applications on the mobile device",
                    "C. It provides the ability to add applications to the mobile device through Cisco ISE",
                    "D. It provides network device administration access"
                ),
                setOf("A"),
                """Mobile Device Management (MDM) software secures, monitors, manages and supports mobile devices deployed across mobile operators, service providers and enterprises. A typical MDM product consists of a policy server, a mobile device client and an optional inline enforcement point that controls the use of some applications on a mobile device (like email) in the deployed environment. However the network is the only entity that can provide granular access to endpoints (based on ACL's, TrustSec SGT's etc). It is envisaged that Cisco Identity Services Engine (ISE) would be an additional network based enforcement point while the MDM policy server would serve as the policy decision point. ISE expects specific data from MDM servers to provide a complete solution
The following are the high level use cases in this solution.
+ Device registration- Non registered endpoints accessing the network on-premises will be redirected to registration page on MDM server for registration based on user role, device type, etc
+ Remediation- Non compliant endpoints will be given restricted access based on compliance state
+ Periodic compliance check – Periodically check with MDM server for compliance
+ Ability for ISE administrators to issue remote actions on the device through the MDM server (e.g.: remote wiping of the managed device)
+ Ability for end user to leverage the ISE My Devices Portal to manage personal devices, e.g. Full Wipe, Corporate Wipe and PIN Lock.""",
                "https://community.cisco.com/t5/security-documents/cisco-ise-integration-with-mobile-device-management-mdm/ta-p/3784691",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "An administrator configures a new destination list in Cisco Umbrella so that the organization can block specific domains for its devices. What should be done to ensure that all subdomains of domain.com are blocked?",
                listOf(
                    "A. Configure the *.com address in the block list.",
                    "B. Configure the *.domain.com address in the block list",
                    "C. Configure the www.domain.com address in the block list",
                    "D. Configure the domain.com address in the block list"
                ),
                setOf("D"),
                """It is not possible to use an asterisk to wildcard a different part of the domain. The following will not work:
*.domain.com
subdomain.*.com
sub*.com
domain.*
Reference: https://docs.umbrella.com/deployment-umbrella/docs/wild-cards
By configuring domain.com address in the block list, we implied to block *.domain.com/* (all subdomains would be blocked too).""",
                "https://docs.umbrella.com/deployment-umbrella/docs/wild-cards",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "An organization wants to provide visibility and to identify active threats in its network using a VM. The organization wants to extract metadata from network packet flow while ensuring that payloads are not retained or transferred outside the network. Which solution meets these requirements?",
                listOf(
                    "A. Cisco Umbrella Cloud",
                    "B. Cisco Stealthwatch Cloud PNM",
                    "C. Cisco Stealthwatch Cloud PCM",
                    "D. Cisco Umbrella On-Premises"
                ),
                setOf("B"),
                """Private Network Monitoring (PNM) provides visibility and threat detection for the on-premises network, delivered from the cloud as a SaaS solution. It is the perfect solution for organizations who prefer SaaS products and desire better awareness and security in their on-premises environments while reducing capital expenditure and operational overhead. It works by deploying lightweight software in a virtual machine or server that can consume a variety of native sources of telemetry or extract metadata from network packet flow. It encrypts this metadata and sends it to the Stealthwatch Cloud analytics platform for analysis. Stealthwatch Cloud consumes metadata only. The packet payloads are never retained or transferred outside the network.
This lab focuses on how to configure a Stealthwatch Cloud Private Network Monitoring (PNM) Sensor, in order to provide visibility and effectively identify active threats, and monitors user and device behavior within on-premises networks.
The Stealthwatch Cloud PNM Sensor is an extremely flexible piece of technology, capable of being utilized in a number of different deployment scenarios. It can be deployed as a complete Ubuntu based virtual appliance on different hypervisors (e.g. –VMware, VirtualBox). It can be deployed on hardware running a number of different Linux-based operating systems.
Reference: https://www.ciscolive.com/c/dam/r/ciscolive/us/docs/2019/pdf/5eU6DfQV/LTRSEC-2240-LG2.pdf""",
                "https://www.ciscolive.com/c/dam/r/ciscolive/us/docs/2019/pdf/5eU6DfQV/LTRSEC-2240-LG2.pdf",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "An organization deploys multiple Cisco FTD appliances and wants to manage them using one centralized solution. The organization does not have a local VM but does have existing Cisco ASAs that must migrate over to Cisco FTDs. Which solution meets the needs of the organization?",
                listOf(
                    "A. Cisco FMC",
                    "B. CSM",
                    "C. Cisco FDM",
                    "D. CDO"
                ),
                setOf("D"),
                """As the organization does not have a local VM so the best solution is using FMC over the cloud. 
FMC can be deployed as a physical or virtual appliance, or from the cloud. It can also be consumed as a service. The cloud-delivered FMC, through CDO, has all the benefits of FMC without the need to manage FMC software update itself.
Reference: https://www.cisco.com/c/en/us/products/collateral/security/firesight-management-center/datasheet-c78-736775.html""",
                "https://www.cisco.com/c/en/us/products/collateral/security/firesight-management-center/datasheet-c78-736775.html",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "An organization wants to secure data in a cloud environment. Its security model requires that all users be authenticated and authorized. Security configuration and posture must be continuously validated before access is granted or maintained to applications and data. There is also a need to allow certain application traffic and deny all other traffic by default. Which technology must be used to implement these requirements?",
                listOf(
                    "A. virtual routing and forwarding",
                    "B. microsegmentation",
                    "C. access control policy",
                    "D. virtual LAN"
                ),
                setOf("B"),
                """Zero Trust is a security framework requiring all users, whether in or outside the organization's network, to be authenticated, authorized, and continuously validated for security configuration and posture before being granted or keeping access to applications and data. Zero Trust assumes that there is no traditional network edge; networks can be local, in the cloud, or a combination or hybrid with resources anywhere as well as workers in any location.
The Zero Trust model uses microsegmentation — a security technique that involves dividing perimeters into small zones to maintain separate access to every part of the network — to contain attacks.""",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "A Cisco FTD engineer is creating a new IKEv2 policy called s2s00123456789 for their organization to allow for additional protocols to terminate network devices with. They currently only have one policy established and need the new policy to be a backup in case some devices cannot support the stronger algorithms listed in the primary policy. What should be done in order to support this?",
                listOf(
                    "A. Change the integrity algorithms to SHA* to support all SHA algorithms in the primary policy",
                    "B. Make the priority for the new policy 5 and the primary policy 1.",
                    "C. Change the encryption to AES* to support all AES algorithms in the primary policy",
                    "D. Make the priority for the primary policy 10 and the new policy 1"
                ),
                setOf("B"),
                """All IKE policies on the device are sent to the remote peer regardless of what is in the selected policy section. The first IKE Policy matched by the remote peer will be selected for the VPN connection. Choose which policy is sent first using the priority field. Priority 1 will be sent first.
Reference: https://www.cisco.com/c/en/us/support/docs/security-vpn/ipsec-negotiation-ike-protocols/215470-site-to-site-vpn-configuration-on-ftd-ma.html""",
                "https://www.cisco.com/c/en/us/support/docs/security-vpn/ipsec-negotiation-ike-protocols/215470-site-to-site-vpn-configuration-on-ftd-ma.html",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "Which type of encryption uses a public key and private key?",
                listOf(
                    "A. asymmetric",
                    "B. symmetric",
                    "C. linear",
                    "D. nonlinear"
                ),
                setOf("A"),
                "",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "What are two features of NetFlow flow monitoring? (Choose two)",
                listOf(
                    "A. Can track ingress and egress information",
                    "B. Include the flow record and the flow importer",
                    "C. Copies all ingress flow information to an interface",
                    "D. Does not required packet sampling on interfaces",
                    "E. Can be used to track multicast, MPLS, or bridged traffic"
                ),
                setOf("A", "E"),
                """The following are restrictions for Flexible NetFlow:
+ Traditional NetFlow (TNF) accounting is not supported.
+ Flexible NetFlow v5 export format is not supported, only NetFlow v9 export format is supported.
+ Both ingress and egress NetFlow accounting is supported.
+ Microflow policing feature shares the NetFlow hardware resource with FNF.
+ Only one flow monitor per interface and per direction is supported.
Reference: https://www.cisco.com/en/US/docs/switches/lan/catalyst3850/software/release/3se/consolidated_guide/b_consolidated_3850_3se_cg_chapter_011010.html
When configuring NetFlow, follow these guidelines and restrictions:
+ Except in PFC3A mode, NetFlow supports bridged IP traffic. PFC3A mode does not support NetFlow bridged IP traffic.
+ NetFlow supports multicast IP traffic.
Reference: https://www.cisco.com/en/US/docs/general/Test/dwerblo/broken_guide/netflow.html
The Flexible NetFlow – MPLS Egress NetFlow feature allows you to capture IP flow information for packets that arrive on a router as Multiprotocol Label Switching (MPLS) packets and are transmitted as IP packets. This feature allows you to capture the MPLS VPN IP flows that are traveling through the service provider backbone from one site of a VPN to another site of the same VPN
Reference: https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/netflow/configuration/15-mt/nf-15-mt-book/cfg-mpls-netflow.html""",
                "https://www.cisco.com/en/US/docs/switches/lan/catalyst3850/software/release/3se/consolidated_guide/b_consolidated_3850_3se_cg_chapter_011010.html",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "A customer has various external HTTP resources available including Intranet Extranet and Internet, with a proxy configuration running in explicit mode. Which method allows the client desktop browsers to be configured to select when to connect direct or when to use the proxy?",
                listOf(
                    "A. Transport mode",
                    "B. Forward file",
                    "C. PAC file",
                    "D. Bridge mode"
                ),
                setOf("C"),
                """A Proxy Auto-Configuration (PAC) file is a JavaScript function definition that determines whether web browser requests (HTTP, HTTPS, and FTP) go direct to the destination or are forwarded to a web proxy server.
PAC files are used to support explicit proxy deployments in which client browsers are explicitly configured to send traffic to the web proxy. The big advantage of PAC files is that they are usually relatively easy to create and maintain.""",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "Which Talos reputation center allows for tracking the reputation of IP addresses for email and web traffic?",
                listOf(
                    "A. IP and Domain Reputation Center",
                    "B. File Reputation Center",
                    "C. IP Slock List Center",
                    "D. AMP Reputation Center"
                ),
                setOf("A"),
                "",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "An engineer is configuring IPsec VPN and needs an authentication protocol that is reliable and supports ACK and sequence. Which protocol accomplishes this goal?",
                listOf(
                    "A. AES-192",
                    "B. IKEv1",
                    "C. AES-256",
                    "D. ESP"
                ),
                setOf("D"),
                "",
                "",
                QuestionCategory.SCOR_PART_3
            )
        )
    }
}
