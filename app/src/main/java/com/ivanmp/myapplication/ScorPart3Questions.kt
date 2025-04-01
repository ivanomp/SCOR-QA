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
            ),
            Question.MultipleChoice(
                "Refer to the exhibit.\nntp authentication-key 10 md5 cisco123\nntp trusted-key 10\nA network engineer is testing NTP authentication and realizes that any device synchronizes time with this router and that NTP authentication is not enforced. What is the cause of this issue?",
                listOf(
                    "A. The hashing algorithm that was used was MD5 which is unsupported.",
                    "B. The key was configured in plain text.",
                    "C. NTP authentication is not enabled.",
                    "D. The router was not rebooted after the NTP configuration updated"
                ),
                setOf("C"),
                """In order to enable NTP, we need an additional command "ntp authenticate".""",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "An administrator is adding a new Cisco ISE node to an existing deployment. What must be done to ensure that the addition of the node will be successful when inputting the FQDN?",
                listOf(
                    "A. Change the IP address of the new Cisco ISE node to the same network as the others",
                    "B. Make the new Cisco ISE node a secondary PAN before registering it with the primary",
                    "C. Open port 8905 on the firewall between the Cisco ISE nodes",
                    "D. Add the DNS entry for the new Cisco ISE node into the DNS server"
                ),
                setOf("D"),
                """You can register Cisco ISE nodes to the primary PAN to form a multinode deployment. Nodes in a deployment other than the primary PAN are referred to as secondary nodes.
…
Ensure that the primary PAN and the node being registered are DNS resolvable to each other.
…
Step 4. Enter the DNS-resolvable fully qualified domain name (FQDN) of the standalone node that you are going to register (in the format hostname.domain-name, for example, abc.xyz.com). The FQDN of the primary PAN and the node being registered must be resolvable from each other.
Reference: https://www.cisco.com/c/en/us/td/docs/security/ise/2-7/admin_guide/b_ise_27_admin_guide/b_ISE_admin_27_deployment.html""",
                "https://www.cisco.com/c/en/us/td/docs/security/ise/2-7/admin_guide/b_ise_27_admin_guide/b_ISE_admin_27_deployment.html",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "Refer to the exhibit.\ncrypto ikev2 name-mangler MANGLER\n dn organization-unit\nAn engineer is implementing a certificate based VPN. What is the result of the existing configuration?",
                listOf(
                    "A. The OU of the IKEv2 peer certificate is used as the identity when matching an IKEv2 authorization policy",
                    "B. Only an IKEv2 peer that has an OU certificate attribute set to MANGLER establishes an IKEv2 SA successfully",
                    "C. The OU of the IKEv2 peer certificate is encrypted when the OU is set to MANGLER",
                    "D. The OU of the IKEv2 peer certificate is set to MANGLER"
                ),
                setOf("A"),
                "",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "An organization wants to implement a cloud-delivered and SaaS-based solution to provide visibility and threat detection across the AWS network. The solution must be deployed without software agents and rely on AWS VPC flow logs instead. Which solution meets these requirements?",
                listOf(
                    "A. Cisco Stealthwatch Cloud",
                    "B. Cisco Umbrella",
                    "C. NetFlow collectors",
                    "D. Cisco Cloudlock"
                ),
                setOf("A"),
                "",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "How is data sent out to the attacker during a DNS tunneling attack?",
                listOf(
                    "A. as part of the UDP'53 packet payload",
                    "B. as part of the domain name",
                    "C. as part of the TCP/53 packet header",
                    "D. as part of the DNS response packet"
                ),
                setOf("B"),
                "",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "A network engineer must configure a Cisco Secure Email Gateway to prompt users to enter two forms of information before gaining access. The Cisco Secure Email Gateway must also join a cluster machine using preshared keys. What must be configured to meet these requirements?",
                listOf(
                    "A. Enable two-factor authentication through a RADIUS server and then join the cluster by using the Cisco Secure Email Gateway CLI",
                    "B. Enable two-factor authentication through a RADIUS server and then join the cluster by using the Cisco Secure Email Gateway GUI",
                    "C. Enable two-factor authentication through a TACACS+ server and then join the cluster by using the Cisco Secure Email Gateway GUI",
                    "D. Enable two-factor authentication through a TACACS+ server and then join the cluster by using the Cisco Secure Email Gateway CLI"
                ),
                setOf("A"),
                """You cannot create or join a cluster from the Graphical User Interface (GUI). You must use the Command Line Interface (CLI) to create, join, or configure clusters of machines. Once you have created a cluster, you can change configuration settings from either the GUI or the CLI.
Reference: https://www.cisco.com/c/en/us/td/docs/security/esa/esa11-0/user_guide_fs/b_ESA_Admin_Guide_11_0/b_ESA_Admin_Guide_chapter_0100111.html
Cisco Secure Email Gateway does not support TACACS+ server.""",
                "https://www.cisco.com/c/en/us/td/docs/security/esa/esa11-0/user_guide_fs/b_ESA_Admin_Guide_11_0/b_ESA_Admin_Guide_chapter_0100111.html",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "What is the term for having information about threats and threat actors that helps mitigate harmful events that would otherwise compromise networks or systems?",
                listOf(
                    "A. trusted automated exchange",
                    "B. Indicators of Compromise",
                    "C. The Exploit Database",
                    "D. threat intelligence"
                ),
                setOf("D"),
                """Threat intelligence is referred to as the knowledge about an existing or emerging threat to assets, including networks and systems. Threat intelligence includes context, mechanisms, indicators of compromise (IoCs), implications, and actionable advice. Threat intelligence is referred to as the information about the observables, IoCs intent, and capabilities of internal and external threat actors and their attacks.
Reference: CCNP and CCIE Security Core SCOR 350-701 Official Cert Guide.""",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "Which Cisco platform processes behavior baselines, monitors for deviations, and reviews for malicious processes in data center traffic and servers while performing software vulnerability detection?",
                listOf(
                    "A. Cisco Secure Workload",
                    "B. Cisco ISE",
                    "C. Cisco AMP for Network",
                    "D. Cisco Secure Client"
                ),
                setOf("A"),
                """What use cases are supported by the Cisco Secure Workload platform (formerly Tetration)?
A. The platform supports the following use cases:
…
+ Process behavior baseline and deviation: Collect the complete process inventory along with the process hash information, baseline the behavior, and identify deviations.
+ Software inventory and vulnerability detection: Identify all the software packages and versions installed on the servers. Using the Common Vulnerabilities and Exposures (CVE) database and additional data feeds, detect if there are any associated vulnerabilities or exposures and take action to protect against active exploit.
Reference: https://www.cisco.com/c/en/us/products/collateral/data-center-analytics/tetration-analytics/q-and-a-c67-737402.html""",
                "https://www.cisco.com/c/en/us/products/collateral/data-center-analytics/tetration-analytics/q-and-a-c67-737402.html",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "Which portion of the network do EPP solutions solely focus on and EDR solutions do not?",
                listOf(
                    "A. server farm",
                    "B. perimeter",
                    "C. core",
                    "D. East-West gateways"
                ),
                setOf("B"),
                "",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "What is a benefit of using Cisco CWS compared to an on-premises Cisco Secure Web Appliance?",
                listOf(
                    "A. Cisco CWS eliminates the need to backhaul traffic through headquarters for remote workers whereas Cisco Secure Web Appliance does not",
                    "B. Cisco CWS minimizes the load on the internal network and security infrastructure as compared to Cisco Secure Web Appliance.",
                    "C. URL categories are updated more frequently on Cisco CWS than they are on Cisco Secure Web Appliance",
                    "D. Content scanning for SAAS cloud applications is available through Cisco CWS and not available through Cisco Secure Web Appliance"
                ),
                setOf("A"),
                """Malware can enter the Cisco network when an infected user PC connects over a direct link in the office or a VPN link from a remote location. For these connections, Cisco IT uses the Cisco Web Security Appliance (WSA) to protect the network from malware intrusion. However, WSA protection is not available when a user connects to the Internet directly, without connecting via the Cisco network, such as when using a public Wi-Fi service in a coffee shop. In this case, the user's PC can become infected with malware, which may disrupt the user's activity, spread to other networks and devices, and present the risk of a data security or privacy breach. Cisco IT uses the Cisco Cloud Web Security (CWS) solution to help protect user PCs from these malware infections.
The Cisco CWS solution, previously known as Cisco Scan Safe, enforces secure communication to and from the Internet. It uses the Cisco AnyConnect Secure Mobility Client 3.0 to provide remote workers the same level of security as onsite employees when using a laptop issued by Cisco.
Reference: https://www.cisco.com/c/dam/en_us/about/ciscoitatwork/borderless_networks/docs/Cloud_Web_Security_IT_Methods.pdf
Cisco ISR with Cloud Web Security Connector:
…
Eliminates the need to backhaul Internet traffic from branch offices, so offices can access the web directly, without losing control of or visibility into web usage.
Reference: https://www.cisco.com/c/en/us/products/collateral/security/router-security/data_sheet_c78-655324.pdf""",
                "https://www.cisco.com/c/en/us/products/collateral/security/router-security/data_sheet_c78-655324.pdf",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "An organization wants to improve its cybersecurity processes and to add intelligence to its data. The organization wants to utilize the most current intelligence data for URL filtering, reputations, and vulnerability information that can be integrated with the Cisco FTD and Cisco WSA. What must be done to accomplish these objectives?",
                listOf(
                    "A. Create a Cisco pxGrid connection to NIST to import this information into the security products for policy use",
                    "B. Create an automated download of the Internet Storm Center intelligence feed into the Cisco FTD and Cisco WSA databases to tie to the dynamic access control policies.",
                    "C. Download the threat intelligence feed from the IETF and import it into the Cisco FTD and Cisco WSA databases",
                    "D. Configure the integrations with Talos Intelligence to take advantage of the threat intelligence that it provides"
                ),
                setOf("D"),
                """We need an automated solution to deal with the rapid change of cybersecurity so answer A and C are not correct.
According to the following facts about Talos, we believe answer D is the best choice:
Cisco WSA detects and correlates threats in real time by tapping into the largest threat-detection network in the world, Cisco Talos. To discover where threats are hiding, Cisco Talos pulls massive quantities of information across multiple vectors – firewall, IPS, web, email, and VPN. Cisco Talos constantly refreshes information every 3 to 5 minutes – adding intelligence to and receiving intelligence from Cisco WSA and other network security devices. This enables Cisco WSA to deliver industry-leading defense hours and even days ahead of competitors.
Reference: https://www.cisco.com/c/en/us/products/collateral/security/web-security-appliance/solution-overview-c22-732948.html
Talos' threat intelligence supports a two-way flow of telemetry and protection across market-leading security solutions including Next-Generation Intrusion Prevention System (NGIPS), Next-Generation Firewall (NGFW), Advanced Malware Protection (AMP), Email Security Appliance (ESA), Cloud Email Security (CES), Cloud Web Security (CWS), Web Security Appliance (WSA), Umbrella, and ThreatGrid, as well as numerous open-source and commercial threat protection systems.
Reference: https://www.talosintelligence.com/docs/Talos_WhitePaper.pdf""",
                "https://www.talosintelligence.com/docs/Talos_WhitePaper.pdf",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "Cisco SensorBase gathers threat information from a variety of Cisco products and services and performs analytics to find patterns on threats. Which term describes this process?",
                listOf(
                    "A. deployment",
                    "B. consumption",
                    "C. authoring",
                    "D. sharing"
                ),
                setOf("A"),
                "",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "An organization has a requirement to collect full metadata information about the traffic going through their AWS cloud services. They want to use this information for behavior analytics and statistics. Which two actions must be taken to implement this requirement? (Choose two)",
                listOf(
                    "A. Configure Cisco ACI to ingest AWS information",
                    "B. Configure Cisco Thousand Eyes to ingest AWS information",
                    "C. Send syslog from AWS to Cisco Stealthwatch Cloud",
                    "D. Send VPC Flow Logs to Cisco Stealthwatch Cloud",
                    "E. Configure Cisco Stealthwatch Cloud to ingest AWS information"
                ),
                setOf("D", "E"),
                "",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "An engineer is configuring their router to send NetfFow data to Stealthwatch which has an IP address of 1.1.1.1 using the flow record Steathwatch406397954 command. Which additional command is required to complete the flow record?",
                listOf(
                    "A. transport udp 2055",
                    "B. match ipv4 ttl",
                    "C. cache timeout active 60",
                    "D. destination 1.1.1.1"
                ),
                setOf("B"),
                """The "transport udp …" command can only be used under flow exporter. The "cache timeout active …" command can only be used under flow monitor.
Under flow record, we cannot type "destination 1.1.1.1". This command can only be used under flow exporter. We can only use the "match ipv4 ttl" command under flow record in this question.
Good reference: https://www.cisco.com/c/dam/en/us/td/docs/security/stealthwatch/netflow/config-trouble-netflow-stealth.pdf""",
                "https://www.cisco.com/c/dam/en/us/td/docs/security/stealthwatch/netflow/config-trouble-netflow-stealth.pdf",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "An engineer needs to add protection for data in transit and have headers in the email message. Which configuration is needed to accomplish this goal?",
                listOf(
                    "A. Provision the email appliance",
                    "B. Deploy an encryption appliance",
                    "C. Map sender IP addresses to a host interface",
                    "D. Enable flagged message handling"
                ),
                setOf("B"),
                "",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "An administrator is adding a new switch onto the network and has configured AAA for network access control. When testing the configuration, the RADIUS authenticates to Cisco ISE but is being rejected. Why is the ip radius source-interface command needed for this configuration?",
                listOf(
                    "A. Only requests that originate from a configured NAS IP are accepted by a RADIUS server",
                    "B. The RADIUS authentication key is transmitted only from the defined RADIUS source interface",
                    "C. RADIUS requests are generated only by a router if a RADIUS source interface is defined",
                    "D. Encrypted RADIUS authentication requires the RADIUS source interface be defined"
                ),
                setOf("A"),
                """The source IP address of the RADIUS packets must match the NAS IP address configured on the RADIUS server. A mismatch leads to RADIUS packet timeout and the server gets marked "DEAD".
Reference: https://www.cisco.com/c/en/us/products/collateral/ios-nx-os-software/identity-based-networking-services/whitepaper_C11-731907.html""",
                "https://www.cisco.com/c/en/us/products/collateral/ios-nx-os-software/identity-based-networking-services/whitepaper_C11-731907.html",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "Refer to the exhibit.\ninterface GigabitEthernet1/0/18\n switchport access vlan 41\n switchport mode access\n switchport voice vlan 44\n device-tracking attach-policy IPDT_MAX_10\n authentication periodic\n authentication timer reauthenticate server\n access-session host-mode multi-domain\n access-session port-control auto\n dot1x pae authenticator\n dot1x timeout tx-period 7\n dot1x max-reauth-req 3\n spanning-tree portfast\n service-policy type control subscriber POLICY_Gi1/0/18\nA Cisco ISE administrator adds a new switch to an 802.1X deployment and has difficulty with some endpoints gaining access. Most PCs and IP phones can connect and authenticate using their machine certificate credentials. However printer and video cameras cannot based on the interface configuration provided. What must be to get these devices on to the network using Cisco ISE for authentication and authorization while maintaining security controls?",
                listOf(
                    "A. Change the default policy in Cisco ISE to allow all devices not using machine authentication",
                    "B. Enable insecure protocols within Cisco ISE in the allowed protocols configuration",
                    "C. Configure authentication event fail retry 2 action authorize vlan 41 on the interface",
                    "D. Add mab to the interface configuration"
                ),
                setOf("D"),
                """What is MAB? MAB stands for MAC Authentication Bypass, this is a form of network authentication that ISE supports by using the endpoints MAC Address to authenticate against an ISE policy set. MAB is used for devices that don't have the capability to support 802.1x e.g. certain printers and other legacy devices.
Reference: https://www.allthingsnetworking.net/ise-mab-wired-configuration/""",
                "https://www.allthingsnetworking.net/ise-mab-wired-configuration/",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "What is the function of the crypto isakmp key cisc406397954 address 0.0.0.0 0.0.0.0 command when establishing an IPsec VPN tunnel?",
                listOf(
                    "A. It defines what data is going to be encrypted via the VPN",
                    "B. It configures the pre-shared authentication key",
                    "C. It prevents all IP addresses from connecting to the VPN server.",
                    "D. It configures the local address for the VPN server."
                ),
                setOf("B"),
                """Note:
+ "address 0.0.0.0 0.0.0.0" means remote peer is any -> any destination can try to negotiate with this router.
+ The Phase 1 password is "cisc406397954".""",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "An engineer is adding a Cisco DUO solution to the current TACACS+ deployment using Cisco ISE. The engineer wants to authenticate users using their account when they log into network devices. Which action accomplishes this task?",
                listOf(
                    "A. Configure Cisco DUO with the external Active Directory connector and tie it to the policy set within Cisco ISE",
                    "B. Install and configure the Cisco DUO Authentication Proxy and configure the identity source sequence within Cisco ISE",
                    "C. Create an identity policy within Cisco ISE to send all authentication requests to Cisco DUO",
                    "D. Modify the current policy with the condition MFASourceSequence DUO=true in the authorization conditions within Cisco ISE"
                ),
                setOf("B"),
                """Duo MFA Integration with ISE for TACACS+ Device Administration with Local/Internal (ISE) Users
In this setup, ISE will forward the TACACS+ authentication requests to the Duo Authentication proxy. The proxy will then punt the requests back to ISE for local user authentication. This can be a little bit confusing but it is necessary for organizations that want to utilize the local user database on ISE and not relay on external identity sources such as Active Directory, LDAP, etc. If the authentication is successful, the end user/admin will be send a "DUO Push." If the local ISE authentication fails, then the process will stop and no "Duo Push" will occur.
1. Admin user initiates a shell connection to a network device where he/she uses Active Directory based credentials
2. Network device forwards the request to the TACACS+ server (ISE)
3. ISE sends the authentication request to Duo's Authentication Proxy
4. The proxy forwards the request back to ISE for the 1st factor authentication
5. ISE informs the Authentication Proxy if the local authentication was successful
6. Upon successful ISE authentication, the Authentication Proxy sends an authentication request to Duo cloud for 2nd factor authentication
7. Duo cloud sends a "push" to the admin user
8. Admin user "approves" the "push"
9. Duo informs the Authentication Proxy of the successful push
10. Authentication proxy informs ISE of a successful Authentication
11. ISE Authorizes the admin user

Therefore answer B is the best choice.""",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "An organization is selecting a cloud architecture and does not want to be responsible for patch management of the operating systems. Why should the organization select either Platform as a Service or Infrastructure as a Service for this environment?",
                listOf(
                    "A. Platform as a Service because the customer manages the operating system",
                    "B. Infrastructure as a Service because the customer manages the operating system",
                    "C. Platform as a Service because the service provider manages the operating system",
                    "D. Infrastructure as a Service because the service provider manages the operating system"
                ),
                setOf("C"),
                """We don't want to manage the OS so we should choose PaaS or SaaS. But this question only wants to compare between PaaS and IaaS so we must choose PaaS.""",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "How does a cloud access security broker function?",
                listOf(
                    "A. It is an authentication broker to enable single sign-on and multi-factor authentication for a cloud solution",
                    "B. It integrates with other cloud solutions via APIs and monitors and creates incidents based on events from the cloud solution",
                    "C. It acts as a security information and event management solution and receives syslog from other cloud solutions",
                    "D. It scans other cloud solutions being used within the network and identifies vulnerabilities"
                ),
                setOf("B"),
                "",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "A Cisco Secure Endpoint administrator configures a custom detection policy to add specific MD5 signatures. The configuration is created in the simple detection policy section, but it does not work. What is the reason for this failure?",
                listOf(
                    "A. The administrator must upload the file instead of the hash for Cisco AMP to use",
                    "B. The MD5 hash uploaded to the simple detection policy is in the incorrect format",
                    "C. The APK must be uploaded for the application that the detection is intended",
                    "D. Detections for MD5 signatures must be configured in the advanced custom detection policies"
                ),
                setOf("D"),
                "",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "What is the difference between a vulnerability and an exploit?",
                listOf(
                    "A. A vulnerability is a hypothetical event for an attacker to exploit",
                    "B. A vulnerability is a weakness that can be exploited by an attacker",
                    "C. An exploit is a weakness that can cause a vulnerability in the network",
                    "D. An exploit is a hypothetical event that causes a vulnerability in the network"
                ),
                setOf("B"),
                """A vulnerability is a weakness in a software system. And an exploit is an attack that leverages that vulnerability.""",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
    "An engineer integrates Cisco FMC and Cisco ISE using pxGrid. Which role is assigned for Cisco FMC?",
    listOf(
        "A. client",
        "B. server",
        "C. publisher",
        "D. controller"
    ),
    setOf("C"),
    """pxGrid stands for Platform Exchange Grid, and it is a technology that allows integrating multiple vendors security products together and grouping them in an ecosystem domain. The main purpose of using pxGrid is to share contextual data between the integrated partners.
pxGrid uses a built-in API in ISE and it is comprised of three main components which are the controller, publisher and the subscriber. The controller is the core component to make everything working and as said is going to be ISE. The publisher instead is the partner that has some contextual data to be shared with the other partners. And finally the subscriber is the partner that is interested in parsing some contextual data from the other partners.
Reference: https://bluenetsec.com/fmc-pxgrid-integration-with-ise/
In fact, according to figure 6-5 of this link https://www.ciscopress.com/articles/article.asp?p=2963461&seqNum=2, FMC is a subscriber but we have no such option so the best answer here is "publisher".""",
    "https://bluenetsec.com/fmc-pxgrid-integration-with-ise/",
    QuestionCategory.SCOR_PART_3
),
Question.MultipleChoice(
    "A network security engineer must export packet captures from the Cisco FMC web browser while troubleshooting an issue. When navigating to the address https://<FMC IP>/capure/CAPI/pcap/test.pcap, an error 403: Forbidden is given instead of the PCAP file. Which action must the engineer take to resolve this issue?",
    listOf(
        "A. Disable the proxy setting on the browser",
        "B. Disable the HTTPS server and use HTTP instead",
        "C. Use the Cisco FTD IP address as the proxy server setting on the browser",
        "D. Enable the HTTPS server for the device platform policy"
    ),
    setOf("D"),
    """When you see this HTTP RESPONSE in a packet capture (PCAP), it's likely that proxy is denying the request.
To verify this, get a policy trace, and look for the exact HTTP REQUEST sent by the client, and match it with the policy rules. You will find either a DENY or Denied by Exception result.
You can then modify the rule to allow this HTTP REQUEST, if appropriate.
Reference: https://knowledge.broadcom.com/external/article/167567/why-do-my-pcaps-show-an-http-response-fr.html
Therefore we should modify the policy to allow HTTPS request.""",
    "https://knowledge.broadcom.com/external/article/167567/why-do-my-pcaps-show-an-http-response-fr.html",
    QuestionCategory.SCOR_PART_3
),
Question.MultipleChoice(
    "Which security solution protects users leveraging DNS-layer security?",
    listOf(
        "A. Cisco Umbrella",
        "B. Cisco ISE",
        "C. Cisco ASA",
        "D. Cisco FTD"
    ),
    setOf("A"),
    "",
    "",
    QuestionCategory.SCOR_PART_3
),
Question.MultipleChoice(
    "What is the result of the\nACME-Router(config)#login block-for 100 attempts 4 within 60\ncommand on a Cisco IOS router?",
    listOf(
        "A. After four unsuccessful log in attempts, the line is blocked for 100 seconds and only permit IP addresses A are permitted in ACL 60",
        "B. After four unsuccessful log in attempts, the line is blocked for 60 seconds and only permit IP addresses C are permitted in ACL 100",
        "C. If four log in attempts fail in 100 seconds, wait for 60 seconds to next log in prompt",
        "D. If four failures occur in 60 seconds, the router goes to quiet mode for 100 seconds"
    ),
    setOf("D"),
    """The following example shows how to configure your router to enter a 100 second quiet period if 15 failed login attempts is exceeded within 100 seconds; all login requests will be denied during the quiet period except hosts from the ACL "myacl."
Router(config)# login block-for 100 attempts 15 within 100
Router(config)# login quiet-mode access-class myacl
Reference: https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_cfg/configuration/xe-16/sec-usr-cfg-xe-16-book/sec-login-enhance.html""",
    "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_cfg/configuration/xe-16/sec-usr-cfg-xe-16-book/sec-login-enhance.html",
    QuestionCategory.SCOR_PART_3
),
Question.MultipleChoice(
    "What is an advantage of network telemetry over SNMP pulls?",
    listOf(
        "A. scalability",
        "B. security",
        "C. encapsulation",
        "D. accuracy"
    ),
    setOf("A"),
    """SNMP uses the pull model when retrieving data from a switch. This model cannot scale for today's high-density platforms, and offers very limited extensibility. The pull model is based on a client sending a request to the switch, then the switch responds to that request. On average, network operators using SNMP poll data every five to thirty minutes. But with today's speeds and scale that's not enough to capture important network events.
…
These traditional models also impose limits like scale and efficiency -> So we can deduce network telemetry is more scalable than SNMP pulls.
Reference: https://blogs.cisco.com/developer/its-time-to-move-away-from-snmp-and-cli-and-use-model-driven-telemetry""",
    "https://blogs.cisco.com/developer/its-time-to-move-away-from-snmp-and-cli-and-use-model-driven-telemetry",
    QuestionCategory.SCOR_PART_3
),
Question.MultipleChoice(
    "What is a benefit of using a multifactor authentication strategy?",
    listOf(
        "A. It provides secure remote access for applications",
        "B. It provides an easy, single sign-on experience against multiple applications",
        "C. It protects data by enabling the use of a second validation of identity",
        "D. It provides visibility into devices to establish device trust"
    ),
    setOf("C"),
    """Multi-factor Authentication (MFA) is an authentication method that requires the user to provide two or more verification factors to gain access to a resource. MFA requires means of verification that unauthorized users won't have.
Note: Single sign-on (SSO) is a property of identity and access management that enables users to securely authenticate with multiple applications and websites by logging in only once with just one set of credentials (username and password). With SSO, the application or website that the user is trying to access relies on a trusted third party to verify that users are who they say they are.""",
    "",
    QuestionCategory.SCOR_PART_3
),
            Question.MultipleChoice(
                "Which feature is leveraged by advanced antimalware capabilities to be an effective endpoint protection platform?",
                listOf(
                    "A. big data",
                    "B. storm centers",
                    "C. sandboxing",
                    "D. blocklisting"
                ),
                setOf("C"),
                "",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "Which system facilitates deploying microsegmentation and multi-tenancy services with a policy-based container?",
                listOf(
                    "A. SDLC",
                    "B. Docker",
                    "C. Lambda",
                    "D. Contiv"
                ),
                setOf("D"),
                """Contiv is an open source project that allows you to deploy micro-segmentation policy-based services in container environments. It offers a higher level of networking abstraction for microservices by providing a policy framework. Contiv has built-in service discovery and service routing functions to allow you to scale out services.
Reference: https://www.ciscopress.com/articles/article.asp?p=3004581&seqNum=2""",
                "https://www.ciscopress.com/articles/article.asp?p=3004581&seqNum=2",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "An engineer is trying to decide between using L2TP or GRE over IPsec for their site-to-site VPN implementation. What must be understood before choosing a solution?",
                listOf(
                    "A. L2TP uses TCP port 47 and GRE over IPsec uses UDP port 1701.",
                    "B. GRE over IPsec cannot be used as a standalone protocol, and L2TP can.",
                    "C. GRE over IPsec adds its own header, and L2TP does not",
                    "D. L2TP is an IP packet encapsulation protocol, and GRE over IPsec is a tunneling protocol."
                ),
                setOf("C"),
                """L2TP uses UDP port 1701 while GRE use IP protocol 47 -> Answer A is not correct.
L2TP stands for Layer 2 Tunneling Protocol while GRE is a simple IP packet encapsulation protocol-> Answer D is not correct
This Oreilly link says: "It is unlikely that you will set up L2TP as a standalone protocol, as it has no authentication and encryption on its own. The more likely scenario is setting up an L2TP/IPsec tunnel". So we understand that L2TP can be set up as a standalone protocol, but should not -> Answer B is not correct.
The CCNP and CCIE Security Core SCOR 350-701 Official Cert Guide book says "the GRE protocol adds its own header (4 bytes plus options) between the payload (data) and the delivery header" while the entire L2TP packet, including payload and L2TP header, is sent within a User Datagram Protocol (UDP) datagram -> Answer C is correct.""",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "What are two functionalities of northbound and southbound APIs within Cisco SDN architecture? (Choose two.)",
                listOf(
                    "A. Southbound APIs are used to define how SDN controllers integrate with applications.",
                    "B. Northbound interfaces utilize OpenFlow and OpFlex to integrate with network devices.",
                    "C. Northbound APIs utilize RESTful API methods such as GET, POST, and DELETE.",
                    "D. Southbound interfaces utilize device configurations such as VLANs and IP addresses.",
                    "E. Southbound APIs utilize CLI, SNMP, and RESTCONF."
                ),
                setOf("C", "E"),
                """Northbound APIs are used to define how SDN controllers integrate with applications -> Answer A is not correct.
 
OpenFlow and OpFlex are Southbound APIs -> Answer B is not correct.
Southbound APIs ultilize NETCONF, RESTCONF, SNMP, Telnet, SSH… -> Answer D is not correct while answer E is correct.""",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "Which two solutions help combat social engineering and phishing at the endpoint level? (Choose two)",
                listOf(
                    "A. Cisco ISEN",
                    "B. Cisco Umbrella",
                    "C. Cisco DNA Center",
                    "D. Cisco TrustSec",
                    "E. Cisco Duo Security"
                ),
                setOf("B", "E"),
                "",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "A network engineer must migrate a Cisco WSA virtual appliance from one physical host to another physical host by using VMware Motion. What is a requirement for both physical hosts?",
                listOf(
                    "A. The hosts must run different versions of Cisco Asyncos",
                    "B. The hosts must run Cisco AsyncOS 10.0 or greater",
                    "C. The hosts must have access to the same defined network",
                    "D. The hosts must use a different datastore than the virtual appliance"
                ),
                setOf("C"),
                """Requirements:
+ Both physical hosts must have the same network configuration.
+ Both physical hosts must have access to the same defined network(s) to which the interfaces on the virtual appliance are mapped.
+ Both physical hosts must have access to the datastore that the virtual appliance uses. This datastore can be a storage area network (SAN) or Network-attached storage (NAS).
+ The Cisco Secure Email Virtual Gateway must have no mail in its queue.
Reference: https://www.cisco.com/c/dam/en/us/td/docs/security/content_security/virtual_appliances/Cisco_Content_Security_Virtual_Appliance_Install_Guide.pdf""",
                "https://www.cisco.com/c/dam/en/us/td/docs/security/content_security/virtual_appliances/Cisco_Content_Security_Virtual_Appliance_Install_Guide.pdf",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "An engineer is implementing Cisco CES in an existing Microsoft Office 365 environment and must route inbound email to Cisco CES addresses. Which DNS record must be modified to accomplish this task?",
                listOf(
                    "A. CNAME",
                    "B. МХ",
                    "C. DKIM",
                    "D. SPF"
                ),
                setOf("B"),
                """In order to route inbound email to Cisco CES addresses we must change the MX record.
 
Reference: https://www.ciscolive.com/c/dam/r/ciscolive/emea/docs/2020/pdf/BRKSEC-3433.pdf
At this point, you are ready to cut over the domain through a Mail Exchange (MX) record change. Work with your DNS administrator to resolve your MX records to the IP addresses for your Cisco Secure Email Cloud instance as provided in your Cisco Secure Email welcome letter.
Reference: https://www.cisco.com/c/en/us/support/docs/security/cloud-email-security/214812-configuring-office-365-microsoft-with.html""",
                "https://www.cisco.com/c/en/us/support/docs/security/cloud-email-security/214812-configuring-office-365-microsoft-with.html",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "Which method of attack is used by a hacker to send malicious code through a web application to an unsuspecting user to request that the victims web browser executes the code?",
                listOf(
                    "A. buffer overflow",
                    "B. SQL injection",
                    "C. browser WGET",
                    "D. cross-site scripting"
                ),
                setOf("D"),
                "",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "What are two ways a network administrator transparently identifies users using Active Directory on the Cisco WSA? (Choose two)",
                listOf(
                    "A. Create an LDAP authentication realm and disable transparent user identification",
                    "B. Deploy a separate eDirectory server, the client IP address is recorded in this server.",
                    "C. Create NTLM or Kerberos authentication realm and enable transparent user identification.",
                    "D. The eDirectory client must be installed on each client workstation",
                    "E. Deploy a separate Active Directory agent such as Cisco Context Directory Agent."
                ),
                setOf("C", "E"),
                """Consider the following when you identify users transparently using Active Directory:
+ Transparent user identification with Active Directory works with an NTLM or Kerberos authentication scheme only. You cannot use it with an LDAP authentication realm that corresponds to an Active Directory instance.
+ Transparent user identification works with the versions of Active Directory supported by an Active Directory agent.
Reference: https://www.cisco.com/c/en/us/td/docs/security/wsa/wsa11-0/user_guide/b_WSA_UserGuide/b_WSA_UserGuide_chapter_01001.html""",
                "https://www.cisco.com/c/en/us/td/docs/security/wsa/wsa11-0/user_guide/b_WSA_UserGuide/b_WSA_UserGuide_chapter_01001.html",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "Which endpoint solution protects a user from a phishing attack?",
                listOf(
                    "A. Cisco AnyConnect with Umbrella Roaming Security module",
                    "B. Cisco AnyConnect with Network Access Manager module",
                    "C. Cisco Identity Services Engine",
                    "D. Cisco AnyConnect with ISE Posture module"
                ),
                setOf("A"),
                """Umbrella Roaming is a cloud-delivered security service for Cisco's next-generation firewall. It protects your employees even when they are off the VPN. No additional agents are required. Simply enable the Umbrella functionality in the Cisco AnyConnect client. You'll get seamless protection against malware, phishing, and command-and-control callbacks wherever your users go.
Reference: https://www.cisco.com/c/en/us/products/security/umbrella/umbrella-roaming.html""",
                "https://www.cisco.com/c/en/us/products/security/umbrella/umbrella-roaming.html",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "An engineer configures Cisco Umbrella and has an identity that references two different policies. Which action ensures that the policy that the identity must use takes precedence over the second one?",
                listOf(
                    "A. Configure only the policy with the most recently changed timestamp.",
                    "B. Make the correct policy first in the policy order.",
                    "C. Configure the default policy to redirect the requests to the correct policy.",
                    "D. Place the policy with the most-specific configuration last in the policy order."
                ),
                setOf("B"),
                "",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "What are two functionalities of SDN Northbound APIs? (Choose two)",
                listOf(
                    "A. Northbound APIs provide a programmable interface for applications to dynamically configure the network.",
                    "B. Northbound APIs form the interface between the SDN controller and business applications.",
                    "C. Northbound APIs use the NETCONF protocol to communicate with applications.",
                    "D. Northbound APIs form the interface between the SDN controller and the network switches or routers.",
                    "E. OpenFlow is a standardized northbound API protocol."
                ),
                setOf("A", "B"),
                """Northbound APIs present an abstraction of network functions with a programmable interface for applications to consume the network services and configure the network dynamically -> Answer A is correct.
Northbound APIs usually use RESTful APIs to communicate with applications -> Answer C is not correct.
 
Southbound APIs form the interface between the SDN controller and the network switches or routers -> Answer D is not correct.
OpenFlow and NETCONF are Southbound APIs used for most SDN implementations -> Answer E is not correct.""",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "What must be enabled to secure SaaS-based applications?",
                listOf(
                    "A. two-factor authentication",
                    "B. end-to-end encryption",
                    "C. application security gateway",
                    "D. modular policy framework"
                ),
                setOf("A"),
                """According to this link, we can use the following to secure SaaS-based applications:
+ Set up single sign-on (SSO) integrations
+ Use multi-factor authentication (MFA) -> Answer A is correct.
+ Install and integrate an identity governance solution
+ Stay up to date""",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "A Cisco ISE engineer configures Central Web Authentication (CWA) for wireless guest access and must have the guest endpoints redirect to the guest portal for authentication and authorization. While testing the policy, the engineer notices that the device is not redirected and instead gets full guest access. What must be done for the redirect to work?",
                listOf(
                    "A. Create an advanced attribute setting of Cisco.cisco-gateway-id=guest within the authorization profile for the authorization policy line that the unauthenticated devices hit.",
                    "B. Tag the guest portal in the CWA part of the Common Tasks section of the authorization profile for the authorization policy line that the unauthenticated devices hit",
                    "C. Add the DACL name for the Airespace ACL configured on the WLC in the Common Tasks section of the authorization profile for the authorization policy line that the unauthenticated devices hit",
                    "D. Use the track movement option within the authorization profile for the authorization policy line that the unauthenticated devices hit"
                ),
                setOf("C"),
                """Using an Authorization Profile to Redirect Guest Endpoints to ISE
As explained in Understanding Guest Flow, when endpoints first access the network, they are authenticated with MAB, and must be redirected to the Guest portal for authorization. ISE comes with a built-in profile called Cisco_WebAuth that references a built-in self-registered Guest portal. The WLC and switch require a preconfigured redirect ACL.
…
AireOS does not support downloadable ACLs. Therefore, ACLs must be configured locally on the wireless controller (or access points in FlexConnect mode). The ACL names must match in both ISE and in AireOS. The figure below indicates for a wireless guest:
 
Reference: https://community.cisco.com/t5/security-documents/ise-guest-access-prescriptive-deployment-guide/ta-p/3640475""",
                "https://community.cisco.com/t5/security-documents/ise-guest-access-prescriptive-deployment-guide/ta-p/3640475",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "What is a difference between Cisco Secure Endpoint and Cisco Umbrella?",
                listOf(
                    "A. Cisco Secure Endpoint prevents, detects, and responds to attacks before damage can be done, and Cisco Umbrella provides the first line of defense against Internet threats.",
                    "B. Cisco Secure Endpoint prevents connections to malicious destinations, and Cisco Umbrella works at the file level to prevent the initial execution of malware.",
                    "C. Cisco Secure Endpoint automatically researches indicators of compromise and confirms threats, and Cisco Umbrella does not",
                    "D. Cisco Secure Endpoint is a cloud-based service, and Cisco Umbrella is not"
                ),
                setOf("A"),
                "",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "What is the intent of a basic SYN flood attack?",
                listOf(
                    "A. to flush the register stack to re-initiate the buffers",
                    "B. to solicit DNS responses",
                    "C. to exceed the threshold limit of the connection queue",
                    "D. to cause the buffer to overflow"
                ),
                setOf("C"),
                """A SYN flood (half-open attack) is a type of denial-of-service (DDoS) attack which aims to make a server unavailable to legitimate traffic by consuming all available server resources. By repeatedly sending initial connection request (SYN) packets, the attacker is able to overwhelm all available ports on a targeted server machine, causing the targeted device to respond to legitimate traffic sluggishly or not at all.""",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "Which open standard creates a framework for sharing threat intelligence in a machine-digestible format?",
                listOf(
                    "A. OpenC2",
                    "B. OpenIoC",
                    "C. STIX",
                    "D. Cybox"
                ),
                setOf("B"),
                """OpenIOC is an open framework, meant for sharing threat intelligence information in a machine-readable format. It was developed by the American cybersecurity firm MANDIANT in November 2011. It is written in eXtensible Markup Language (XML) and can be easily customized for additional intelligence so that incident responders can translate their knowledge into a standard format. Organizations can leverage this format to share threat-related latest Indicators of Compromise (IoCs) with other organizations, enabling real-time protection against the latest threats.""",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "Which two methods must be used to add switches into the fabric so that administrators can control how switches are added into DCNM for private cloud management? (Choose two)",
                listOf(
                    "A. PowerOn Auto Provisioning",
                    "B. Cisco Cloud Director",
                    "C. Seed IP",
                    "D. CDP AutoDiscovery",
                    "E. Cisco Prime Infrastructure"
                ),
                setOf("A", "C"),
                """Cisco Data Center Network Manager (DCNM) offers network management system (NMS) support for traditional or multiple-tenant LAN and SAN fabrics. Cisco DCNM uses PowerOn Auto Provisioning (POAP) to automate the process of upgrading software images and installing configuration files on Cisco Nexus switches that are being deployed in the network.
Reference: https://www.cisco.com/c/en/us/products/collateral/cloud-systems-management/prime-data-center-network-manager/guide-c07-740626.html""",
                "https://www.cisco.com/c/en/us/products/collateral/cloud-systems-management/prime-data-center-network-manager/guide-c07-740626.html",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "Which role is a default guest type in Cisco ISE?",
                listOf(
                    "A. Full-Time",
                    "B. Contractor",
                    "C. Yearly",
                    "D. Monthly"
                ),
                setOf("B"),
                """Each guest account must be associated with a guest type. Guest types allow a sponsor to assign different levels of access and different network connection times to a guest account. These guest types are associated with particular network access policies. Cisco ISE includes these default guest types:
Contractor – Users who need access to the network for an extended amount of time, up to a year.
Daily – Guests who need access to the resources on the network for just 1 to 5 days.
Weekly – Users who need access to the network for a couple of weeks.
Reference: https://www.cisco.com/c/en/us/td/docs/security/ise/1-3/admin_guide/b_ise_admin_guide_13/b_ise_admin_guide_sample_chapter_01111.html""",
                "https://www.cisco.com/c/en/us/td/docs/security/ise/1-3/admin_guide/b_ise_admin_guide_13/b_ise_admin_guide_sample_chapter_01111.html",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "An engineer configures new features within the Cisco Umbrella dashboard and wants to identify and proxy traffic that is categorized as risky domains and may contain safe and malicious content. Which action accomplishes these objectives?",
                listOf(
                    "A. Configure intelligent proxy within Cisco Umbrella to intercept and proxy the requests for only those categories",
                    "B. Upload the threat intelligence database to Cisco Umbrella for the most current information on reputations and to have the destination lists block them.",
                    "C. Create a new site within Cisco Umbrella to block requests from those categories so they can be sent to the proxy device.",
                    "D. Configure URL filtering within Cisco Umbrella to track the URLs and proxy the requests for those categories and below."
                ),
                setOf("A"),
                """The 'greylist' of risky domains is compromised of domains that host both malicious and safe content—we consider these "risky" domains. These sites often allow users to upload and share content—making them difficult to police, even for the admins of the site.
Reference: https://docs.umbrella.com/deployment-msp/docs/what-is-the-intelligent-proxy
In order to enable intelligent proxy, we need to use "Advanced Settings":
 """,
                "https://docs.umbrella.com/deployment-msp/docs/what-is-the-intelligent-proxy",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "An administrator enables Cisco Threat Intelligence Director on a Cisco FMC. Which process uses STIX and allows uploads and downloads of block lists?",
                listOf(
                    "A. consumption",
                    "B. editing",
                    "C. sharing",
                    "D. authoring"
                ),
                setOf("A"),
                "",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "Why is it important to have a patching strategy for endpoints?",
                listOf(
                    "A. so that functionality is increased on a faster scale when it is used",
                    "B. so that known vulnerabilities are targeted and having a regular patch cycle reduces risks",
                    "C. so that patching strategies can assist with disabling nonsecure protocols in applications",
                    "D. to take advantage of new features released with patches"
                ),
                setOf("B"),
                "",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "What is a description of microsegmentation?",
                listOf(
                    "A. Environments deploy a container orchestration platform, such as Kubernetes, to manage the application delivery",
                    "B. Environments apply a zero-trust model and specify how applications on different servers or containers can communicate",
                    "C. Environments implement private VLAN segmentation to group servers with similar applications",
                    "D. Environments deploy centrally managed host-based firewall rules on each server or container"
                ),
                setOf("B"),
                """Zero Trust is a security framework requiring all users, whether in or outside the organization's network, to be authenticated, authorized, and continuously validated for security configuration and posture before being granted or keeping access to applications and data. Zero Trust assumes that there is no traditional network edge; networks can be local, in the cloud, or a combination or hybrid with resources anywhere as well as workers in any location.
The Zero Trust model uses microsegmentation — a security technique that involves dividing perimeters into small zones to maintain separate access to every part of the network — to contain attacks.""",
                "",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "Which security product enables administrators to deploy Kubernetes clusters in air-gapped sites without needing Internet access?",
                listOf(
                    "A. Cisco Container Controller",
                    "B. Cisco Container Platform",
                    "C. Cisco Cloud Platform",
                    "D. Cisco Content Platform"
                ),
                setOf("B"),
                """The ability to deploy Kubernetes clusters in air-gapped sites
Cisco Container Platform (CCP) tenant images contain all the necessary binaries and don't need internet access to function.
Reference: https://www.cisco.com/c/en/us/products/cloud-systems-management/container-platform/index.html#~stickynav=3""",
                "https://www.cisco.com/c/en/us/products/cloud-systems-management/container-platform/index.html#~stickynav=3",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "What are two functions of TAXII in threat intelligence sharing? (Choose two)",
                listOf(
                    "A. exchanges trusted anomaly intelligence information",
                    "B. determines how threat intelligence information is relayed",
                    "C. determines the \"what\" of threat intelligence",
                    "D. supports STIX information and allows users to describe threat motivations and abilities"
                ),
                setOf("A", "B"),
                """In short, TAXII is about how parties communicate to exchange threat intelligence and STIX is about describing that threat intelligence in a structured way.
Reference: https://logsentinel.com/blog/the-importance-of-threat-intelligence-sharing-through-taxii-and-stix/?cookie-state-change=1639912854054
STIX states the "what" of threat intelligence, while TAXII defines "how" that information is relayed.
Reference: https://www.anomali.com/resources/what-are-stix-taxii""",
                "https://www.anomali.com/resources/what-are-stix-taxii",
                QuestionCategory.SCOR_PART_3
            ),
            Question.MultipleChoice(
                "An engineer must modify a policy to block specific addresses using Cisco Umbrella. The policy is created already and is actively used by devices, using many of the default policy elements. What else must be done to accomplish this task?",
                listOf(
                    "A. Create a destination list for addresses to be allowed or blocked",
                    "B. Use content categories to block or allow specific addresses",
                    "C. Add the specified addresses to the identities list and create a block action",
                    "D. Modify the application settings to allow only applications to connect to required addresses"
                ),
                setOf("A"),
                """Content Categories – Allows you to block access to categories of websites – groupings of sites with similarly themed content. For example, sports, gambling, or astrology…, not specific addresses -> Answer B is not correct.
Application Settings – Allows you to block access to specific applications (not specific addresses). For example, Netflix, Facebook, or Amazon -> Answer D is not correct.
Destination Lists allows you to create a unique list of destinations (for example, domain name or URL) to which you can block or allow access -> Answer A is correct.
Reference: https://docs.umbrella.com/deployment-umbrella/docs/customize-your-policies-1
An identity list cannot be an address as Umbrella uses the following identities:Network, Network Device, Roaming Computers, Mobile Devices, Chrome Book, Network Tunnel and WebUsers and Groups.
Reference: https://www.cisco.com/c/dam/en/us/solutions/collateral/enterprise/design-zone-security/umbrella-design-guide.pdf""",
                "https://docs.umbrella.com/deployment-umbrella/docs/customize-your-policies-1",
                QuestionCategory.SCOR_PART_3
            ),
            Question.DragAndDrop(
                question = "Drag and drop the cloud security assessment components from the left onto the definitions on the right.",
                items = listOf(
                    "cloud data protection assessment",
                    "cloud security strategy workshop",
                    "cloud security architecture assessment",
                    "user entity behavior assessment"
                ),
                categories = listOf(
                    "understand the security posture of the data or activity taking place in public cloud deployments",
                    "develop a cloud security strategy and roadmap aligned to business priorities",
                    "identify strengths and areas for improvement in the current security architecture during onboarding",
                    "detect potential anomalies in user behavior that suggest malicious behavior in a Software-as-a-Service application"
                ),
                correctMapping = mapOf(
                    "cloud data protection assessment" to "understand the security posture of the data or activity taking place in public cloud deployments",
                    "cloud security strategy workshop" to "develop a cloud security strategy and roadmap aligned to business priorities",
                    "cloud security architecture assessment" to "identify strengths and areas for improvement in the current security architecture during onboarding",
                    "user entity behavior assessment" to "detect potential anomalies in user behavior that suggest malicious behavior in a Software-as-a-Service application"
                ),
                explanation = """Cloud Data Protection Assessment: We review the security posture of documents stored in one Software-as-a-Service (SaaS) instance, or review the activity taking place in an Infrastructure-as-a-Service (IaaS) deployment over a period of time.

Cloud Data Architecture Assessment: We conduct whiteboarding sessions, interviews, and documentation reviews to assess the security architecture of your cloud environment

Cloud User Entity Behavior Assessment: We examine how the users provisioned in a SaaS instance behave, establishes a baseline for each individual user, and monitor user activity

Cloud Security Strategy: Our experts educate your team on cloud security as related to current and future states, as well as business priorities""",
                reference = "https://www.cisco.com/c/dam/en/us/products/security/security-strategy-advisory-aag.pdf",
                category = QuestionCategory.SCOR_PART_3
            ),
            Question.DragAndDrop(
                question = "Drag and drop the features of Cisco ASA with Cisco Firepower from the left onto the benefits on the right.",
                items = listOf(
                    "NGIPS",
                    "Collective Security Intelligence",
                    "AMP",
                    "Full Context Awareness"
                ),
                categories = listOf(
                    "threat prevention and mitigation for known and unknown threats",
                    "real-time threat intelligence and security protection",
                    "detection, blocking and remediation to protect the enterprise against targeted malware attacks",
                    "policy enforcement based on complete visibility of users and communication between virtual machines"
                ),
                correctMapping = mapOf(
                    "NGIPS" to "threat prevention and mitigation for known and unknown threats",
                    "Collective Security Intelligence" to "real-time threat intelligence and security protection",
                    "AMP" to "detection, blocking and remediation to protect the enterprise against targeted malware attacks",
                    "Full Context Awareness" to "policy enforcement based on complete visibility of users and communication between virtual machines"
                ),
                explanation = """Cisco ASA with FirePOWER Services combines the proven security capabilities of the ASA firewall with industry-leading Sourcefire threat and advanced malware protection features in a single device. The solution uniquely provides integrated threat defense across the entire attack continuum: before, during, and after an attack.

NGIPS (Next-Generation Intrusion Prevention System) provides superior threat prevention and mitigation for known and unknown threats.

Collective Security Intelligence provides real-time threat intelligence and security protection through Cisco's Talos Security Intelligence and Research Group.

AMP (Advanced Malware Protection) provides detection, blocking, tracking, analysis, and remediation to protect the enterprise against targeted persistent malware attacks.

Full Context Awareness provides policy enforcement based on complete visibility of users and communication between virtual machines.""",
                reference = "",
                category = QuestionCategory.SCOR_PART_3
            )
        )
    }
}
