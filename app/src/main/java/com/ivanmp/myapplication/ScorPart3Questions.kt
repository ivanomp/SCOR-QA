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
            ),
            Question.MultipleChoice(
                "An administrator is establishing a new site-to-site VPN connection on a Cisco IOS router. The organization needs to ensure that the ISAKMP key on the hub is used only for terminating traffic from the IP address of 172.19.20.24. Which command on the hub will allow the administrator to accomplish this?",
                listOf(
                    "A. crypto ca identity 172.19.20.24",
                    "B. crypto isakmp key Cisco0123456789 172.19.20.24",
                    "C. crypto enrollment peer address 172.19.20.24",
                    "D. crypto isakmp identity address 172.19.20.24"
                ),
                setOf("B"),
                """The command "crypto isakmp identity address 172.19.20.24" is not valid. We can only use "crypto isakmp identity {address | hostname}. The following example uses preshared keys at two peers and sets both their ISAKMP identities to the IP address.
At the local peer (at 10.0.0.1) the ISAKMP identity is set and the preshared key is specified:
crypto isakmp identity address
crypto isakmp key sharedkeystring address 192.168.1.33
At the remote peer (at 192.168.1.33) the ISAKMP identity is set and the same preshared key is specified:
crypto isakmp identity address
crypto isakmp key sharedkeystring address 10.0.0.1
Reference: https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/a1/sec-a1-cr-book/sec-cr-c4.html#wp3880782430
The command "crypto enrollment peer address" is not valid either.
The command "crypto ca identity …" is only used to declare a trusted CA for the router and puts you in the ca-identity configuration mode. Also it should be followed by a name, not an IP address. For example: "crypto ca identity CA-Server" -> Answer A is not correct.
Only answer B is the best choice left.""",
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/a1/sec-a1-cr-book/sec-cr-c4.html#wp3880782430",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "What is a difference between an XSS attack and an SQL injection attack?",
                listOf(
                    "A. SQL injection is a hacking method used to attack SQL databases, whereas XSS attacks can exist in many different types of applications",
                    "B. XSS is a hacking method used to attack SQL databases, whereas SQL injection attacks can exist in many different types of applications",
                    "C. SQL injection attacks are used to steal information from databases whereas XSS attacks are used to redirect users to websites where attackers can steal data from them",
                    "D. XSS attacks are used to steal information from databases whereas SQL injection attacks are used to redirect users to websites where attackers can steal data from them"
                ),
                setOf("C"),
                """In XSS, an attacker will try to inject his malicious code (usually malicious links) into a database. When other users follow his links, their web browsers are redirected to websites where attackers can steal data from them. In a SQL Injection, an attacker will try to inject SQL code (via his browser) into forms, cookies, or HTTP headers that do not use data sanitizing or validation methods of GET/POST parameters.""",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "An engineer has been tasked with configuring a Cisco FTD to analyze protocol fields and detect anomalies in the traffic from industrial systems. What must be done to meet these requirements?",
                listOf(
                    "A. Implement pre-filter policies for the CIP preprocessor",
                    "B. Enable traffic analysis in the Cisco FTD",
                    "C. Configure intrusion rules for the DNP3 preprocessor",
                    "D. Modify the access control policy to trust the industrial traffic"
                ),
                setOf("C"),
                """The Modbus, DNP3, and CIP SCADA preprocessors detect traffic anomalies and provide data to intrusion rules. Therefore in this question only answer A or answer C is correct.
The DNP3 preprocessor detects anomalies in DNP3 traffic and decodes the DNP3 protocol for processing by the rules engine, which uses DNP3 keywords to access certain protocol fields.
The Common Industrial Protocol (CIP) is a widely used application protocol that supports industrial automation applications. EtherNet/IP is an implementation of CIP that is used on Ethernet-based networks. The CIP preprocessor detects CIP and ENIP traffic running on TCP or UDP and sends it to the intrusion rules engine. You can use CIP and ENIP keywords in custom intrusion rules to detect attacks in CIP and ENIP traffic.
Reference: https://www.cisco.com/c/en/us/td/docs/security/firepower/630/configuration/guide/fpmc-config-guide-v63/scada_preprocessors.html
Both DNP3 and CIP preprocessors can be used to detect anomalies but we choose DNP3 as pre-filter policies cannot be used to detect anomalies. To detect anomalies we need to use intrusion rules.
Note:
+ An intrusion rule is a specified set of keywords and arguments that the system uses to detect attempts to exploit vulnerabilities in your network. As the system analyzes network traffic, it compares packets against the conditions specified in each rule, and triggers the rule if the data packet meets all the conditions specified in the rule.
+ Preprocessor rules, which are rules associated with preprocessors and packet decoder detection options in the network analysis policy. Most preprocessor rules are disabled by default.""",
                "https://www.cisco.com/c/en/us/td/docs/security/firepower/630/configuration/guide/fpmc-config-guide-v63/scada_preprocessors.html",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "Which posture assessment requirement provides options to the client for remediation and requires the remediation within a certain timeframe?",
                listOf(
                    "A. Audit",
                    "B. Mandatory",
                    "C. Optional",
                    "D. Visibility"
                ),
                setOf("B"),
                """A posture requirement is a set of compound conditions with an associated remediation action that can be linked with a role and an operating system. All the clients connecting to your network must meet mandatory requirements during posture evaluation to become compliant on the network.
Posture-policy requirements can be set to mandatory, optional, or audit types in posture policies. If requirements are optional and clients fail these requirements, then the clients have an option to continue during posture evaluation of endpoints.
Mandatory Requirements
During policy evaluation, the agent provides remediation options to clients who fail to meet the mandatory requirements defined in the posture policy. End users must remediate to meet the requirements within the time specified in the remediation timer settings.
For example, you have specified a mandatory requirement with a user-defined condition to check the existence of C:\\temp\\text.file in the absolute path. If the file does not exist, the mandatory requirement fails and the user will be moved to Non-Compliant state.
Reference: https://www.cisco.com/c/en/us/td/docs/security/ise/1-4/admin_guide/b_ise_admin_guide_14/b_ise_admin_guide_14_chapter_010111.html""",
                "https://www.cisco.com/c/en/us/td/docs/security/ise/1-4/admin_guide/b_ise_admin_guide_14/b_ise_admin_guide_14_chapter_010111.html",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "Which attribute has the ability to change during the RADIUS CoA?",
                listOf(
                    "A. NTP",
                    "B. authorization",
                    "C. accessibility",
                    "D. membership"
                ),
                setOf("B"),
                """The RADIUS Change of Authorization (CoA) feature provides a mechanism to change the attributes of an authentication, authorization, and accounting (AAA) session after it is authenticated.
Reference: https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_aaa/configuration/15-sy/sec-usr-aaa-15-sy-book/sec-rad-coa.html""",
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_aaa/configuration/15-sy/sec-usr-aaa-15-sy-book/sec-rad-coa.html",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "With Cisco Secure Endpoint, which option shows a list of all files that have been executed in your environment?",
                listOf(
                    "A. prevalence",
                    "B. file analysis",
                    "C. detections",
                    "D. vulnerable software",
                    "E. threat root cause"
                ),
                setOf("A"),
                """Prevalence allows you to view files that have been executed in your deployment.
Note: Threat Root Cause shows how malware is getting onto your computers.
Reference: https://docs.amp.cisco.com/en/A4E/AMP%20for%20Endpoints%20User%20Guide.pdf""",
                "https://docs.amp.cisco.com/en/A4E/AMP%20for%20Endpoints%20User%20Guide.pdf",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "A company discovered an attack propagating through their network via a file. A custom file policy was created in order to track this in the future and ensure no other endpoints execute the infected file. In addition, it was discovered during testing that the scans are not detecting the file as an indicator of compromise. What must be done in order to ensure that the created is functioning as it should?",
                listOf(
                    "A. Create an IP block list for the website from which the file was downloaded",
                    "B. Block the application that the file was using to open",
                    "C. Upload the hash for the file into the policy",
                    "D. Send the file to Cisco Threat Grid for dynamic analysis"
                ),
                setOf("C"),
                "",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "A network engineer is trying to figure out whether FlexVPN or DMVPN would fit better in their environment. They have a requirement for more stringent security multiple security associations for the connections, more efficient VPN establishment as well consuming less bandwidth. Which solution would be best for this and why?",
                listOf(
                    "A. DMVPN because it supports IKEv2 and FlexVPN does not.",
                    "B. FlexVPN because it supports IKEv2 and DMVPN does not.",
                    "C. FlexVPN because it uses multiple SAs and DMVPN does not.",
                    "D. DMVPN because it uses multiple SAs and FlexVPN does not."
                ),
                setOf("C"),
                """FlexVPN supports IKEv2 -> Answer A is not correct.
DMVPN supports both IKEv1 & IKEv2 -> Answer B is not correct.
FlexVPN support multiple SAs -> Answer D is not correct.
Therefore answer C is the best choice left.""",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "How does Cisco Workload Optimization Manager help mitigate application performance issues?",
                listOf(
                    "A. It deploys an AWS Lambda system",
                    "B. It automates resource resizing",
                    "C. It optimizes a flow path",
                    "D. It sets up a workload forensic score"
                ),
                setOf("B"),
                """Cisco Workload Optimization Manager provides specific real-time actions that ensure workloads get the resources they need when they need them, enabling continuous placement, resizing, and capacity decisions that can be automated, driving continuous health in the environment. You can automate the software's decisions according to your level of comfort: recommend (view only), manual (select and apply), or automated (executed in real time by software).
Reference: https://www.cisco.com/c/dam/en/us/solutions/collateral/data-center-virtualization/one-enterprise-suite/solution-overview-c22-739078.pdf""",
                "https://www.cisco.com/c/dam/en/us/solutions/collateral/data-center-virtualization/one-enterprise-suite/solution-overview-c22-739078.pdf",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "An organization configures Cisco Umbrella to be used for its DNS services. The organization must be able to block traffic based on the subnet that the endpoint is on but it sees only the requests from its public IP address instead of each internal IP address. What must be done to resolve this issue?",
                listOf(
                    "A. Set up a Cisco Umbrella virtual appliance to internally field the requests and see the traffic of each IP address",
                    "B. Use the tenant control features to identify each subnet being used and track the connections within the Cisco Umbrella dashboard",
                    "C. Install the Microsoft Active Directory Connector to give IP address information stitched to the requests in the Cisco Umbrella dashboard",
                    "D. Configure an internal domain within Cisco Umbrella to help identify each address and create policy from the domains"
                ),
                setOf("A"),
                """Umbrella virtual appliances (VAs) are lightweight virtual machines that are compatible with VMWare ESX/ESXi, Windows Hyper-V, and KVM hypervisors and the Microsoft Azure, Google Cloud Platform, and Amazon Web Services cloud platforms. When utilized as conditional DNS forwarders on your network, Umbrella VAs record the internal IP address information of DNS requests for usage in reports, security enforcement, and category filtering policies.
VAs act as conditional DNS forwarders in your network, intelligently forwarding public DNS queries to Cisco Umbrella's global network, and local DNS queries to your existing local DNS servers and forwarders. Every public DNS query sent to Umbrella is encrypted, authenticated, and includes the client's internal IP address.
 
Reference: https://docs.umbrella.com/deployment-umbrella/docs/1-introduction
If you're already pointing DNS to Umbrella, or plan to, all the DNS traffic visible in your Umbrella reports come from a single Network identity. The VAs provide internal IP visibility, allowing you to track down malicious or inappropriate traffic within your network to a specific IP address.
Without Virtual Appliances
Security and DNS traffic-related investigations cannot be traced back to an individual computer or IP address.
 
With Virtual Appliances
VAs record the internal IP address of every DNS request. Security and DNS traffic-related investigations allow you to associate traffic to an individual, internal IP address.
 
Reference: https://docs.umbrella.com/deployment-umbrella/docs/1-introduction""",
                "https://docs.umbrella.com/deployment-umbrella/docs/1-introduction",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "What is a difference between a DoS attack and a DDoS attack?",
                listOf(
                    "A. A DoS attack is where a computer is used to flood a server with TCP and UDP packets whereas a DDoS attack is where multiple systems target a single system with a DoS attack.",
                    "B. A DoS attack is where a computer is used to flood a server with TCP and UDP packets whereas a DDoS attack is where a computer is used to flood multiple servers that are distributed over a LAN",
                    "C. A DoS attack is where a computer is used to flood a server with UDP packets whereas a DDoS attack is where a computer is used to flood a server with TCP packets",
                    "D. A DoS attack is where a computer is used to flood a server with TCP packets whereas a DDoS attack is where a computer is used to flood a server with UDP packets"
                ),
                setOf("A"),
                "",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "Which two capabilities of Integration APIs are utilized with Cisco DNA center? (Choose two)",
                listOf(
                    "A. Automatically deploy new virtual routers",
                    "B. Upgrade software on switches and routers",
                    "C. Third party reporting",
                    "D. Connect to ITSM Platforms",
                    "E. Create new SSIDs on a wireless LAN controller"
                ),
                setOf("C", "D"),
                """Integration API (Westbound)
Integration capabilities are part of Westbound interfaces. To meet the need to scale and accelerate operations in modern data centers, IT operators require intelligent, end-to-end work flows built with open APIs. The Cisco DNA Center platform provides mechanisms for integrating Cisco DNA Assurance workflows and data with third-party IT Service Management (ITSM) solutions.
Reference: https://developer.cisco.com/docs/dna-center/#!cisco-dna-center-platform-overview/events-and-notifications-eastbound
-> Therefore answer D is correct.
Westbound—Integration APIs
Cisco DNA Center platform can power end-to-end IT processes across the value chain by integrating various domains such as ITSM, IPAM, and reporting. By leveraging the REST-based Integration Adapter APIs, bi-directional interfaces can be built to allow the exchange of contextual information between Cisco DNA Center and the external, third-party IT systems. The westbound APIs provide the capability to publish the network data, events and notifications to the external systems and consume information in Cisco DNA Center from the connected systems.
Reference: https://blogs.cisco.com/networking/with-apis-cisco-dna-center-can-improve-your-competitive-advantage
-> Answer C is correct.""",
                "https://developer.cisco.com/docs/dna-center/#!cisco-dna-center-platform-overview/events-and-notifications-eastbound",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "Which kind of API that is used with Cisco DNA Center provisions SSIDs, QoS policies, and update software versions on switches?",
                listOf(
                    "A. integration",
                    "B. intent",
                    "C. event",
                    "D. multivendor"
                ),
                setOf("B"),
                """Northbound-Intent APIs
Intent APIs enable developers to access Cisco DNA Center Automation and Assurance workflows. Through this access, you can simplify the process of creating workflows that consolidate multiple network actions.
Say, for instance, you're configuring an SSID on a wireless network. Using Cisco DNA Center and the intent APIs, you can offload the process of setting WLAN and security settings. This saves time and provides greater consistency. You can do the same for QoS policies, software images running on the network devices, and application health.
Reference: https://www.publicnow.com/view/3057F243685FA76A88EFC1651CAAFD66B5B849FE?1603802892""",
                "https://www.publicnow.com/view/3057F243685FA76A88EFC1651CAAFD66B5B849FE?1603802892",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "What is the purpose of CA in a PKI?",
                listOf(
                    "A. to issue and revoke digital certificates.",
                    "B. to validate the authenticity of a digital certificate",
                    "C. to create the private key for a digital certificate.",
                    "D. to certify the ownership of a public key by the named subject"
                ),
                setOf("A"),
                """A trusted CA is the only entity that can issue trusted digital certificates. This is extremely important because while PKI manages more of the encryption side of these certificates, authentication is vital to understanding which entities own what keys. Without a trusted CA, anyone can issue their own keys, authentication goes out the window and chaos ensues.
Reference: https://cheapsslsecurity.com/blog/understanding-the-role-of-certificate-authorities-in-pki/""",
                "https://cheapsslsecurity.com/blog/understanding-the-role-of-certificate-authorities-in-pki/",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "Which DevSecOps implementation process gives a weekly or daily update instead of monthly or quarterly in the applications?",
                listOf(
                    "A. orchestration",
                    "B. CI/CD pipeline",
                    "C. container",
                    "D. security"
                ),
                setOf("B"),
                """Unlike the traditional software life cycle, the CI/CD implementation process gives a weekly or daily update instead of monthly or quarterly. The fun part is customers won't even realize the update is in their applications, as they happen on the fly.
Reference: https://devops.com/how-to-implement-an-effective-ci-cd-pipeline/""",
                "https://devops.com/how-to-implement-an-effective-ci-cd-pipeline/",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "Which parameter is required when configuring a Netflow exporter on a Cisco Router?",
                listOf(
                    "A. DSCP value",
                    "B. source interface",
                    "C. exporter name",
                    "D. exporter description"
                ),
                setOf("C"),
                """An example of configuring a NetFlow exporter is shown below:
flow exporter Exporter
 destination 192.168.100.22
 transport udp 2055
!""",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "Which category includes Dos Attacks?",
                listOf(
                    "A. virus attacks",
                    "B. trojan attacks",
                    "C. flood attacks",
                    "D. phishing attacks"
                ),
                setOf("C"),
                "",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "What are two advantages of using Cisco Any connect over DMVPN? (Choose two)",
                listOf(
                    "A. It provides spoke-to-spoke communications without traversing the hub",
                    "B. It allows different routing protocols to work over the tunnel",
                    "C. It allows customization of access policies based on user identity",
                    "D. It allows multiple sites to connect to the data center",
                    "E. It enables VPN access for individual users from their machines"
                ),
                setOf("C", "E"),
                "",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "When choosing an algorithm to us, what should be considered about Diffie Hellman and RSA for key establishment?",
                listOf(
                    "A. RSA is an asymmetric key establishment algorithm intended to output symmetric keys.",
                    "B. RSA is a symmetric key establishment algorithm intended to output asymmetric keys.",
                    "C. DH is a symmetric key establishment algorithm intended to output asymmetric keys.",
                    "D. DH is on asymmetric key establishment algorithm intended to output symmetric keys."
                ),
                setOf("D"),
                """Diffie Hellman (DH) uses a private-public key pair to establish a shared secret, typically a symmetric key. DH is not a symmetric algorithm – it is an asymmetric algorithm used to establish a shared secret for a symmetric key algorithm.""",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "Which type of DNS abuse exchanges data between two computers even when there is no direct connection?",
                listOf(
                    "A. malware installation",
                    "B. command-and-control communication",
                    "C. network footprinting",
                    "D. data exfiltration"
                ),
                setOf("D"),
                """Malware installation: This may be done by hijacking DNS queries and responding with malicious IP addresses.
Command & Control communication: As part of lateral movement, after an initial compromise, DNS communications is abused to communicate with a C2 server. This typically involves making periodic DNS queries from a computer in the target network for a domain controlled by the adversary. The responses contain encoded messages that may be used to perform unauthorized actions in the target network.
Network footprinting: Adversaries use DNS queries to build a map of the network. Attackers live off the terrain so developing a map is important to them.
Data theft (exfiltration): Abuse of DNS to transfer data; this may be performed by tunneling other protocols like FTP, SSH through DNS queries and responses. Attackers make multiple DNS queries from a compromised computer to a domain owned by the adversary. DNS tunneling can also be used for executing commands and transferring malware into the target network.
Reference: https://www.netsurion.com/articles/5-types-of-dns-attacks-and-how-to-detect-them""",
                "https://www.netsurion.com/articles/5-types-of-dns-attacks-and-how-to-detect-them",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "What is a difference between GETVPN and IPsec?",
                listOf(
                    "A. GETVPN reduces latency and provides encryption over MPLS without the use of a central hub",
                    "B. GETVPN provides key management and security association management",
                    "C. GETVPN is based on IKEv2 and does not support IKEv1",
                    "D. GETVPN is used to build a VPN network with multiple sites without having to statically configure all devices"
                ),
                setOf("A"),
                """By using GETVPN together with DMVPN, the delay caused by IPsec tunnel negotiation is eliminated because connections are static.
Reference: Network Security Technologies and Solutions (CCIE Professional Development) Book
Moreover, GETVPN is a site-to-site VPN so it does not require a central hub.""",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "What is a benefit of using telemetry over SNMP to configure new routers for monitoring purposes?",
                listOf(
                    "A. Telemetry uses a pull, method which makes it more reliable than SNMP",
                    "B. Telemetry uses push and pull, which makes it more scalable than SNMP",
                    "C. Telemetry uses push and pull which makes it more secure than SNMP",
                    "D. Telemetry uses a push method which makes it faster than SNMP"
                ),
                setOf("D"),
                """SNMP polling can often be in the order of 5-10 minutes, CLIs are unstructured and prone to change which can often break scripts.
The traditional use of the pull model, where the client requests data from the network does not scale when what you want is near real-time data.
Moreover, in some use cases, there is the need to be notified only when some data changes, like interfaces status, protocol neighbors change etc.
Model-Driven Telemetry is a new approach for network monitoring in which data is streamed from network devices continuously using a push model and provides near real-time access to operational statistics.
Referfence: https://developer.cisco.com/docs/ios-xe/#!streaming-telemetry-quick-start-guide/streaming-telemetry""",
                "https://developer.cisco.com/docs/ios-xe/#!streaming-telemetry-quick-start-guide/streaming-telemetry",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "An organization wants to use Cisco FTD or Cisco ASA devices. Specific URLs must be blocked from being accessed via the firewall which requires that the administrator input the bad URL categories that the organization wants blocked into the access policy. Which solution should be used to meet this requirement?",
                listOf(
                    "A. Cisco ASA because it enables URL filtering and blocks malicious URLs by default, whereas Cisco FTD does not",
                    "B. Cisco ASA because it includes URL filtering in the access control policy capabilities, whereas Cisco FTD does not",
                    "C. Cisco FTD because it includes URL filtering in the access control policy capabilities, whereas Cisco ASA does not",
                    "D. Cisco FTD because it enables URL filtering and blocks malicious URLs by default, whereas Cisco ASA does not"
                ),
                setOf("C"),
                "",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "An administrator configures a Cisco WSA to receive redirected traffic over ports 80 and 443. The organization requires that a network device with specific WSA integration capabilities be configured to send the traffic to the WSA to proxy the requests and increase visibility, while making this invisible to the users. What must be done on the Cisco WSA to support these requirements?",
                listOf(
                    "A. Configure transparent traffic redirection using WCCP in the Cisco WSA and on the network device",
                    "B. Configure active traffic redirection using WPAD in the Cisco WSA and on the network device",
                    "C. Use the Layer 4 setting in the Cisco WSA to receive explicit forward requests from the network device",
                    "D. Use PAC keys to allow only the required network devices to send the traffic to the Cisco WSA"
                ),
                setOf("A"),
                "",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "An administrator configures new authorization policies within Cisco ISE and has difficulty profiling the devices. Attributes for the new Cisco IP phones that are profiled based on the RADIUS authentication are seen however the attributes for CDP or DHCP are not. What should the administrator do to address this issue?",
                listOf(
                    "A. Configure the ip dhcp snooping trust command on the DHCP interfaces to get the information to Cisco ISE",
                    "B. Configure the authentication port-control auto feature within Cisco ISE to identify the devices that are trying to connect",
                    "C. Configure a service template within the switch to standardize the port configurations so that the correct information is sent to Cisco ISE",
                    "D. Configure the device sensor feature within the switch to send the appropriate protocol information"
                ),
                setOf("D"),
                """Device sensor is a feature of access devices. It allows to collect information about connected endpoints. Mostly, information collected by Device Sensor can come from the following protocols:
+ Cisco Discovery Protocol (CDP)
+ Link Layer Discovery Protocol (LLDP)
+ Dynamic Host Configuration Protocol (DHCP)
Reference: https://www.cisco.com/c/en/us/support/docs/security/identity-services-engine/200292-Configure-Device-Sensor-for-ISE-Profilin.html""",
                "https://www.cisco.com/c/en/us/support/docs/security/identity-services-engine/200292-Configure-Device-Sensor-for-ISE-Profilin.html",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "A network engineer must monitor user and device behavior within the on-premises network. This data must be sent to the Cisco Stealthwatch Cloud analytics platform for analysis. What must be done to meet this requirement using the Ubuntu-based VM appliance deployed in a VMware-based hypervisor?",
                listOf(
                    "A. Configure a Cisco FMC to send syslogs to Cisco Stealthwatch Cloud",
                    "B. Deploy the Cisco Stealthwatch Cloud PNM sensor that sends data to Cisco Stealthwatch Cloud",
                    "C. Deploy a Cisco FTD sensor to send network events to Cisco Stealthwatch Cloud",
                    "D. Configure a Cisco FMC to send NetFlow to Cisco Stealthwatch Cloud"
                ),
                setOf("B"),
                """The Stealthwatch Cloud Private Network Monitoring (PNM) Sensor is an extremely flexible piece of technology, capable of being utilized in a number of different deployment scenarios. It can be deployed as a complete Ubuntu based virtual appliance on different hypervisors (e.g. –VMware, VirtualBox). It can be deployed on hardware running a number of different Linux-based operating systems.
Reference: https://www.ciscolive.com/c/dam/r/ciscolive/us/docs/2019/pdf/5eU6DfQV/LTRSEC-2240-LG2.pdf""",
                "https://www.ciscolive.com/c/dam/r/ciscolive/us/docs/2019/pdf/5eU6DfQV/LTRSEC-2240-LG2.pdf",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "An organization uses Cisco FMC to centrally manage multiple Cisco FTD devices. The default management port conflicts with other communications on the network and must be changed. What must be done to ensure that all devices can communicate together?",
                listOf(
                    "A. Manually change the management port on Cisco FMC and all managed Cisco FTD devices",
                    "B. Set the tunnel to go through the Cisco FTD",
                    "C. Change the management port on Cisco FMC so that it pushes the change to all managed Cisco FTD devices",
                    "D. Set the tunnel port to 8305"
                ),
                setOf("A"),
                """The FMC and managed devices communicate using a two-way, SSL-encrypted communication channel, which by default is on port 8305.
Cisco strongly recommends that you keep the default settings for the remote management port, but if the management port conflicts with other communications on your network, you can choose a different port. If you change the management port, you must change it for all devices in your deployment that need to communicate with each other.
Reference: https://www.cisco.com/c/en/us/td/docs/security/firepower/misc/fmc-ftd-mgmt-nw/fmc-ftd-mgmt-nw.html""",
                "https://www.cisco.com/c/en/us/td/docs/security/firepower/misc/fmc-ftd-mgmt-nw/fmc-ftd-mgmt-nw.html",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "Which service allows a user export application usage and performance statistics with Cisco Application Visibility and control?",
                listOf(
                    "A. SNORT",
                    "B. NetFlow",
                    "C. SNMP",
                    "D. 802.1X"
                ),
                setOf("B"),
                """Application Visibility and control (AVC) supports NetFlow to export application usage and performance statistics. This data can be used for analytics, billing, and security policies.""",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "An engineer adds a custom detection policy to a Cisco AMP deployment and encounters issues with the configuration. The simple detection mechanism is configured, but the dashboard indicates that the hash is not 64 characters and is non-zero. What is the issue?",
                listOf(
                    "A. The engineer is attempting to upload a hash created using MD5 instead of SHA-256",
                    "B. The file being uploaded is incompatible with simple detections and must use advanced detections",
                    "C. The hash being uploaded is part of a set in an incorrect format",
                    "D. The engineer is attempting to upload a file instead of a hash"
                ),
                setOf("A"),
                "",
                "",
                QuestionCategory.SCOR_PART_3
            )
        )
    }
}
