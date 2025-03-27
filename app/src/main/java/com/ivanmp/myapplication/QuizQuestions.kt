package com.ivanmp.myapplication

object QuizQuestions {
    private val allQuestions = mutableListOf<Question>()
    private var currentBatchStart = 0
    private const val BATCH_SIZE = 50

    // Initialize questions
    init {
        // Add your questions here
        allQuestions.addAll(listOf(
            Question.MultipleChoice(
                "What is a characteristic of a bridge group in ASA Firewall transparent mode?",
                listOf(
                    "A. It allows the ASA to act as a Layer 2 device",
                    "B. It requires IP addresses on the bridge group interfaces",
                    "C. It supports dynamic routing protocols",
                    "D. It can only be used with VLANs"
                ),
                setOf("A"),
                "A bridge group in transparent mode allows the ASA to act as a Layer 2 device, forwarding traffic based on MAC addresses rather than IP addresses.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
            ),
            Question.DragAndDrop(
                "Categorize the following capabilities into either Cisco Firepower or Cisco AMP:",
                listOf(
                    "Network-based malware protection",
                    "File reputation and sandboxing",
                    "Endpoint visibility and control",
                    "Application visibility and control",
                    "Network access control",
                    "Threat intelligence integration"
                ),
                listOf("Cisco Firepower", "Cisco AMP"),
                mapOf(
                    "Network-based malware protection" to "Cisco Firepower",
                    "File reputation and sandboxing" to "Cisco AMP",
                    "Endpoint visibility and control" to "Cisco AMP",
                    "Application visibility and control" to "Cisco Firepower",
                    "Network access control" to "Cisco Firepower",
                    "Threat intelligence integration" to "Cisco Firepower"
                ),
                "Cisco Firepower provides network-focused security features like network-based malware protection, application control, and network access control. Cisco AMP focuses on endpoint security with features like file reputation, sandboxing, and endpoint visibility.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
            ),
            Question.MultipleChoice(
                "When Cisco and other industry organizations publish and inform users of known security findings and vulnerabilities, which name is used?",
                listOf(
                    "A. Common Security Exploits",
                    "B. Common Vulnerabilities and Exposures",
                    "C. Common Exploits and Vulnerabilities",
                    "D. Common Vulnerabilities, Exploits and Threats"
                ),
                setOf("B"),
                "The industry standard identifier for public vulnerability disclosure is the Common Vulnerabilities and Exposures (CVE), sponsored by US-CERT.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
            ),
            Question.MultipleChoice(
                "Which two fields are defined in the NetFlow flow? (Choose two)",
                listOf(
                    "A. type of service byte",
                    "B. class of service bits",
                    "C. Layer 4 protocol type",
                    "D. destination port",
                    "E. output logical interface"
                ),
                setOf("A", "D"),
                "NetFlow v5 defines a flow with seven key fields including the type of service byte and the destination port, among others.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
            ),
            Question.MultipleChoice(
                "What provides the ability to program and monitor networks from somewhere other than the DNAC GUI?",
                listOf(
                    "A. NetFlow",
                    "B. Desktop client",
                    "C. ASDM",
                    "D. API"
                ),
                setOf("D"),
                "APIs enable network management and monitoring programmatically outside the default DNAC GUI environment.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
            ),
            Question.MultipleChoice(
                "An organization has two machines hosting web applications. Machine 1 is vulnerable to SQL injection while machine 2 is vulnerable to buffer overflows. What action would allow the attacker to gain access to machine 1 but not machine 2?",
                listOf(
                    "A. sniffing the packets between the two hosts",
                    "B. sending continuous pings",
                    "C. overflowing the buffer's memory",
                    "D. inserting malicious commands into the database"
                ),
                setOf("D"),
                "SQL injection attacks target databases by inserting malicious commands, which would affect Machine 1 but not Machine 2 which is vulnerable to buffer overflows.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
            ),
            Question.MultipleChoice(
                "An organization is trying to improve their Defense in Depth by blocking malicious destinations prior to a connection being established. The solution must be able to block certain applications from being used within the network. Which product should be used to accomplish this goal?",
                listOf(
                    "A. Cisco Firepower",
                    "B. Cisco Umbrella",
                    "C. ISE",
                    "D. AMP"
                ),
                setOf("B"),
                "Cisco Umbrella protects users from accessing malicious domains by proactively analyzing and blocking unsafe destinations – before a connection is ever made. Thus it can protect from phishing attacks by blocking suspicious domains when users click on the given links that an attacker sent.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
            ),
            Question.MultipleChoice(
                "A company is experiencing exfiltration of credit card numbers that are not being stored on-premise. The company needs to be able to protect sensitive data throughout the full environment. Which tool should be used to accomplish this goal?",
                listOf(
                    "A. Security Manager",
                    "B. Cloudlock",
                    "C. Web Security Appliance",
                    "D. Cisco ISE"
                ),
                setOf("B"),
                "Cisco Cloudlock is a cloud-native cloud access security broker (CASB) that helps you move to the cloud safely. It protects your cloud users, data, and apps. Cisco Cloudlock provides visibility and compliance checks, protects data against misuse and exfiltration, and provides threat protections against malware like ransomware.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
            ),
            Question.MultipleChoice(
                "An engineer is trying to securely connect to a router and wants to prevent insecure algorithms from being used. However, the connection is failing. Which action should be taken to accomplish this goal?",
                listOf(
                    "A. Disable telnet using the no ip telnet command",
                    "B. Enable the SSH server using the ip ssh server command",
                    "C. Configure the port using the ip ssh port 22 command",
                    "D. Generate the RSA key using the crypto key generate rsa command"
                ),
                setOf("D"),
                "In this question, the engineer was trying to secure the connection so maybe he was trying to allow SSH to the device. But maybe something went wrong so the connection was failing (the connection used to be good). So maybe he was missing the 'crypto key generate rsa' command.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
            ),
            Question.MultipleChoice(
                "A network administrator is using the Cisco Secure Email Gateway with AMP to upload files to the cloud for analysis. The network is congested and is affecting communication. How will the Cisco Secure Email Gateway handle any files which need analysis?",
                listOf(
                    "A. AMP calculates the SHA-256 fingerprint, caches it, and periodically attempts the upload",
                    "B. The file is queued for upload when connectivity is restored",
                    "C. The file upload is abandoned",
                    "D. The Secure Email Gateway immediately makes another attempt to upload the file"
                ),
                setOf("C"),
                "The appliance will try once to upload the file; if upload is not successful, for example because of connectivity problems, the file may not be uploaded. If the failure was because the file analysis server was overloaded, the upload will be attempted once more. In this question, it stated 'the network is congested' (not the file analysis server was overloaded) so the appliance will not try to upload the file again.",
                "https://www.cisco.com/c/en/us/support/docs/security/email-security-appliance/118796-technote-esa-00.html"
            ),
            Question.MultipleChoice(
                "Which type of algorithm provides the highest level of protection against brute-force attacks?",
                listOf(
                    "A. PFS",
                    "B. HMAC",
                    "C. MD5",
                    "D. SHA"
                ),
                setOf("D"),
                "SHA (Secure Hash Algorithm) provides the highest level of protection against brute-force attacks due to its cryptographic strength and resistance to collision attacks.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
            ),
            Question.MultipleChoice(
                "What must be configured in Cisco ISE to enforce reauthentication of an endpoint session when an endpoint is deleted from an identity group?",
                listOf(
                    "A. posture assessment",
                    "B. CoA",
                    "C. external identity source",
                    "D. SNMP probe"
                ),
                setOf("B"),
                "Cisco ISE allows a global configuration to issue a Change of Authorization (CoA) in the Profiler Configuration page that enables the profiling service with more control over endpoints that are already authenticated. One of the settings to configure the CoA type is 'Reauth'. This option is used to enforce reauthentication of an already authenticated endpoint when it is profiled.",
                "https://www.cisco.com/c/en/us/td/docs/security/ise/1-3/admin_guide/b_ise_admin_guide_13/b_ise_admin_guide_sample_chapter_010101.html"
            ),
            Question.MultipleChoice(
                "A network administrator is configuring a rule in an access control policy to block certain URLs and selects the \"Chat and Instant Messaging\" category. Which reputation score should be selected to accomplish this goal?",
                listOf(
                    "A. 1",
                    "B. 3",
                    "C. 5",
                    "D. 10"
                ),
                setOf("D"),
                "We choose \"Chat and Instant Messaging\" category in \"URL Category\". To block certain URLs we need to choose URL Reputation from 6 to 10.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
            ),
            Question.MultipleChoice(
                "Which group within Cisco writes and publishes a weekly newsletter to help cybersecurity professionals remain aware of the ongoing and most prevalent threats?",
                listOf(
                    "A. PSIRT",
                    "B. Talos",
                    "C. CSIRT",
                    "D. DEVNET"
                ),
                setOf("B"),
                "Talos Threat Source is a regular intelligence update from Cisco Talos, highlighting the biggest threats each week and other security news.",
                "https://talosintelligence.com/newsletters"
            ),
            Question.MultipleChoice(
                "What are the two types of managed Intercloud Fabric deployment models? (Choose two)",
                listOf(
                    "A. Service Provider managed",
                    "B. Public managed",
                    "C. Hybrid managed",
                    "D. User managed",
                    "E. Enterprise managed"
                ),
                setOf("A", "E"),
                "Cisco Intercloud Fabric addresses the cloud deployment requirements appropriate for two hybrid cloud deployment models: Enterprise Managed (an enterprise manages its own cloud environments) and Service Provider Managed (the service provider administers and controls all cloud resources).",
                "https://www.cisco.com/c/en/us/td/docs/solutions/Hybrid_Cloud/Intercloud/Intercloud_Fabric.pdf"
            ),
            Question.MultipleChoice(
                "What are two DDoS attack categories? (Choose two)",
                listOf(
                    "A. sequential",
                    "B. protocol",
                    "C. database",
                    "D. volume-based",
                    "E. screen-based"
                ),
                setOf("B", "D"),
                "While DDoS offer a less complicated attack mode than other forms of cyberattacks, they are growing stronger and more sophisticated. There are three basic categories of attack: volume-based attacks, which use high traffic to inundate the network bandwidth; protocol attacks, which focus on exploiting server resources; and application attacks, which focus on web applications and are considered the most sophisticated and serious type of attacks.",
                "https://www.esecurityplanet.com/networks/types-of-ddos-attacks/"
            ),
            Question.MultipleChoice(
                "An organization received a large amount of SPAM messages over a short time period. In order to take action on the messages, it must be determined how harmful the messages are and this needs to happen dynamically. What must be configured to accomplish this?",
                listOf(
                    "A. Configure the Cisco Secure Web Appliance to modify policies based on the traffic seen",
                    "B. Configure the Cisco Secure Email Gateway to receive real-time updates from Talos",
                    "C. Configure the Cisco Secure Web Appliance to receive real-time updates from Talos",
                    "D. Configure the Cisco Secure Email Gateway to modify policies based on the traffic seen"
                ),
                setOf("B"),
                "In order to fight spams dynamically, the best way is to configure Secure Email Gateway to receive real-time updates from Talos.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
            ),
            Question.MultipleChoice(
                "Which product allows Cisco FMC to push security intelligence observable to its sensors from other products?",
                listOf(
                    "A. Encrypted Traffic Analytics",
                    "B. Threat Intelligence Director",
                    "C. Cognitive Threat Analytics",
                    "D. Cisco Talos Intelligence"
                ),
                setOf("B"),
                "Threat Intelligence Director allows Cisco FMC to push security intelligence observable to its sensors from other products.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
            ),
            Question.MultipleChoice(
                "What are two differences between a Cisco WSA that is running in transparent mode and one running in explicit mode? (Choose two)",
                listOf(
                    "A. When the Cisco WSA is running in transparent mode, it uses the WSA's own IP address as the HTTP request destination",
                    "B. The Cisco WSA responds with its own IP address only if it is running in explicit mode",
                    "C. The Cisco WSA is configured in a web browser only if it is running in transparent mode",
                    "D. The Cisco WSA uses a Layer 3 device to redirect traffic only if it is running in transparent mode",
                    "E. The Cisco WSA responds with its own IP address only if it is running in transparent mode"
                ),
                setOf("B", "D"),
                "When requests are being redirected to the WSA transparently, the WSA must pretend to be the OCS (origin content server), since the client is unaware of the existence of a proxy. On the contrary, if a request is explicitly sent to the WSA, the WSA will respond with its own IP information. In transparent mode deployments, network infrastructure devices redirect web traffic to the proxy using Layer 3 devices.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
            ),
            Question.MultipleChoice(
                "After a recent breach, an organization determined that phishing was used to gain initial access to the network before regaining persistence. The information gained from the phishing attack was a result of users visiting known malicious websites. What must be done in order to prevent this from happening in the future?",
                listOf(
                    "A. Modify an access policy",
                    "B. Modify identification profiles",
                    "C. Modify outbound malware scanning policies",
                    "D. Modify web proxy settings"
                ),
                setOf("A"),
                "URL conditions in access control rules allow you to limit the websites that users on your network can access. This feature is called URL filtering. Using category and reputation data also simplifies policy creation and administration. It grants you assurance that the system will control web traffic as expected.",
                "https://www.cisco.com/c/en/us/td/docs/security/firepower/60/configuration/guide/fpmc-config-guide-v60/Access_Control_Rules__URL_Filtering.html"
            ),
            Question.MultipleChoice(
                "What is the function of SDN southbound API protocols?",
                listOf(
                    "A. to allow for the dynamic configuration of control plane applications",
                    "B. to enable the controller to make changes",
                    "C. to enable the controller to use REST",
                    "D. to allow for the static configuration of control plane applications"
                ),
                setOf("B"),
                "Southbound APIs enable SDN controllers to dynamically make changes based on real-time demands and scalability needs.",
                "https://www.ciscopress.com/articles/article.asp?p=3004581&seqNum=2"
            ),
            Question.MultipleChoice(
                question = "Refer to the exhibit.\n\nTraffic is not passing through IPsec site-to-site VPN on the Firepower Threat Defense appliance. What is causing this issue?",
                options = listOf(
                    "A. No split-tunnel policy is defined on the Firepower Threat Defense appliance",
                    "B. The access control policy is not allowing VPN traffic in",
                    "C. Site-to-site VPN peers are using different encryption algorithms",
                    "D. Site-to-site VPN preshared keys are mismatched"
                ),
                correct = setOf("B"),
                explanation = "If sysopt permit-vpn is not enabled then an access control policy must be created to allow the VPN traffic through the FTD device. If sysopt permit-vpn is enabled skip creating an access control policy.",
                reference = "https://www.cisco.com/c/en/us/support/docs/security-vpn/ipsec-negotiation-ike-protocols/215470-site-to-site-vpn-configuration-on-ftd-ma.html",
                imageResourceName = "question_23_ipsec_output"
            ),
            Question.MultipleChoice(
                question = "An attacker needs to perform reconnaissance on a target system to help gain access to it. The system has weak passwords, no encryption on the VPN links, and software bugs on the system's applications. Which vulnerability allows the attacker to see the passwords being transmitted in clear text?",
                options = listOf(
                    "A. weak passwords for authentication",
                    "B. unencrypted links for traffic",
                    "C. software bugs on applications",
                    "D. improper file security"
                ),
                correct = setOf("B"),
                explanation = "Unencrypted links for traffic allow attackers to see passwords being transmitted in clear text. This is a critical security vulnerability as it exposes sensitive information during transmission.",
                reference = "https://www.cisco.com/c/en/us/support/docs/security-vpn/ipsec-negotiation-ike-protocols/14106-how-to-ipsec.html"
            ),
            Question.MultipleChoice(
                question = "Using Cisco Firepower's Security Intelligence policies, upon which two criteria is Firepower block based? (Choose two)",
                options = listOf(
                    "A. URLs",
                    "B. protocol IDs",
                    "C. IP addresses",
                    "D. MAC addresses",
                    "E. port numbers"
                ),
                correct = setOf("A", "C"),
                explanation = "Security Intelligence Sources can block specific IP addresses, URLs, or domain names using a manually-created list or feed. For IP addresses, you can also use network objects or groups.",
                reference = "https://www.cisco.com/c/en/us/td/docs/security/firepower/623/configuration/guide/fpmc-config-guide-v623/security_intelligence_blacklisting.html"
            ),
            Question.MultipleChoice(
                question = "Which Cisco platform ensures that machines that connect to organizational networks have the recommended antivirus definitions and patches to help prevent an organizational malware outbreak?",
                options = listOf(
                    "A. Cisco WiSM",
                    "B. Cisco Secure Email Gateway",
                    "C. Cisco ISE",
                    "D. Cisco Prime Infrastructure"
                ),
                correct = setOf("C"),
                explanation = "A posture policy is a collection of posture requirements, which are associated with one or more identity groups, and operating systems. We can configure ISE to check for the Windows patch at Work Centers > Posture > Posture Elements > Conditions > File.",
                reference = "https://www.cisco.com/c/en/us/td/docs/security/ise/2-6/admin_guide/b_ise_admin_guide_26/b_ise_admin_guide_26_chapter_01100.html"
            ),
            Question.MultipleChoice(
                question = "What are two benefits of Flexible NetFlow records? (Choose two)",
                options = listOf(
                    "A. They allow the user to configure flow information to perform customized traffic identification",
                    "B. They provide attack prevention by dropping the traffic",
                    "C. They provide accounting and billing enhancements",
                    "D. They converge multiple accounting technologies into one accounting mechanism",
                    "E. They provide monitoring of a wider range of IP packet information from Layer 2 to 4"
                ),
                correct = setOf("A", "D"),
                explanation = "Key Advantages to using Flexible NetFlow: Flexibility, scalability of flow data beyond traditional NetFlow, user configurable flow information to perform customized traffic identification, and convergence of multiple accounting technologies into one accounting mechanism.",
                reference = "https://www.cisco.com/c/en/us/products/collateral/ios-nx-os-software/flexible-netflow/product_data_sheet0900aecd804b590b.html"
            ),
            Question.MultipleChoice(
                question = "How does DNS Tunneling exfiltrate data?",
                options = listOf(
                    "A. An attacker registers a domain that a client connects to based on DNS records and sends malware through that connection.",
                    "B. An attacker opens a reverse DNS shell to get into the client's system and install malware on it.",
                    "C. An attacker uses a non-standard DNS port to gain access to the organization's DNS servers in order to poison the resolutions.",
                    "D. An attacker sends an email to the target with hidden DNS resolvers in it to redirect them to a malicious domain."
                ),
                correct = setOf("A"),
                explanation = "DNS tunneling exfiltrates data by registering a domain that a client connects to based on DNS records and sending malware through that connection. This technique can bypass traditional security controls by using DNS traffic which is often allowed through firewalls.",
                reference = "https://www.cisco.com/c/en/us/support/docs/security/email-security-appliance/118007-configure-esa-00.html"
            ),
            Question.MultipleChoice(
                question = "A user has a device in the network that is receiving too many connection requests from multiple machines. Which type of attack is the device undergoing?",
                options = listOf(
                    "A. phishing",
                    "B. slowloris",
                    "C. pharming",
                    "D. SYN flood"
                ),
                correct = setOf("D"),
                explanation = "A SYN flood attack is a type of denial-of-service attack where an attacker sends a succession of SYN requests to a target's system in an attempt to consume enough server resources to make the system unresponsive to legitimate traffic.",
                reference = "https://www.cisco.com/c/en/us/support/docs/security-vpn/ipsec-negotiation-ike-protocols/14106-how-to-ipsec.html"
            ),
            Question.MultipleChoice(
                question = "An organization is receiving SPAM emails from a known malicious domain. What must be configured in order to prevent the session during the initial TCP communication?",
                options = listOf(
                    "A. Configure the Cisco Secure Email Gateway to drop the malicious emails",
                    "B. Configure policies to quarantine malicious emails",
                    "C. Configure policies to stop and reject communication",
                    "D. Configure the Cisco Secure Email Gateway to reset the TCP connection"
                ),
                correct = setOf("C"),
                explanation = "Each Mail Flow Policy has an access rule, such as ACCEPT, REJECT, RELAY, CONTINUE, and TCPREFUSE. A host that attempts to establish a connection to your Secure Email Gateway and matches a Sender Group using a TCPREFUSE access rule is not allowed to connect to your Secure Email Gateway.",
                reference = "https://www.cisco.com/c/en/us/support/docs/security/email-security-appliance/118007-configure-esa-00.html"
            ),
            Question.MultipleChoice(
                question = "A Cisco Firepower administrator needs to configure a rule to allow a new application that has never been seen on the network. Which two actions should be selected to allow the traffic to pass without inspection? (Choose two)",
                options = listOf(
                    "A. permit",
                    "B. trust",
                    "C. reset",
                    "D. allow",
                    "E. monitor"
                ),
                correct = setOf("B", "D"),
                explanation = "Each rule also has an action, which determines whether you monitor, trust, block, or allow matching traffic. With action 'trust', Firepower does not do any more inspection on the traffic. There will be no intrusion protection and also no file-policy on this traffic.",
                reference = "https://www.cisco.com/c/en/us/td/docs/security/firepower/623/configuration/guide/fpmc-config-guide-v623/access_control_policies.html"
            ),
            Question.MultipleChoice(
                question = "An engineer needs behavioral analysis to detect malicious activity on the hosts, and is configuring the organization's public cloud to send telemetry using the cloud provider's mechanisms to a security device. Which mechanism should the engineer configure to accomplish this goal?",
                options = listOf(
                    "A. mirror port",
                    "B. sFlow",
                    "C. NetFlow",
                    "D. VPC flow logs"
                ),
                correct = setOf("D"),
                explanation = "AWS recently introduced VPC Flow Logs, which facilitate logging of all the IP traffic to, from, and across your network. These logs are stored as records in special Amazon CloudWatch log groups and provide the same kind of information as NetFlow data.",
                reference = "https://www.cisco.com/c/en/us/products/collateral/security/stealthwatch-cloud/at-a-glance-c45-739851.html"
            ),
            Question.MultipleChoice(
                question = "An engineer has enabled LDAP accept queries on a listener. Malicious actors must be prevented from quickly identifying all valid recipients. What must be done on the Cisco Secure Email Gateway to accomplish this goal?",
                options = listOf(
                    "A. Configure incoming content filters",
                    "B. Use Bounce Verification",
                    "C. Configure Directory Harvest Attack Prevention",
                    "D. Bypass LDAP access queries in the recipient access table"
                ),
                correct = setOf("C"),
                explanation = "A Directory Harvest Attack (DHA) is a technique used by spammers to find valid/existent email addresses at a domain either by using Brute force or by guessing valid e-mail addresses at a domain using different permutations of common username.",
                reference = "https://www.cisco.com/c/en/us/support/docs/security/email-security-appliance/118007-configure-esa-00.html"
            ),
            Question.MultipleChoice(
                question = "What is a feature of Cisco NetFlow Secure Event Logging for Cisco ASAs?",
                options = listOf(
                    "A. Multiple NetFlow collectors are supported",
                    "B. Advanced NetFlow v9 templates and legacy v5 formatting are supported",
                    "C. Secure NetFlow connections are optimized for Cisco Prime Infrastructure",
                    "D. Flow-create events are delayed"
                ),
                correct = setOf("D"),
                explanation = "The ASA and ASASM implementations of NetFlow Secure Event Logging (NSEL) provide the following major functions: Delays the export of flow-create events.",
                reference = "https://www.cisco.com/c/en/us/td/docs/security/asa/asa92/configuration/general/asa-general-cli/monitor-nsel.pdf"
            ),
            Question.MultipleChoice(
                question = "An engineer is configuring 802.1X authentication on Cisco switches in the network and is using CoA as a mechanism. Which port on the firewall must be opened to allow the CoA traffic to traverse the network?",
                options = listOf(
                    "A. TCP 6514",
                    "B. UDP 1700",
                    "C. TCP 49",
                    "D. UDP 1812"
                ),
                correct = setOf("B"),
                explanation = "CoA Messages are sent on two different udp ports depending on the platform. Cisco standardizes on UDP port 1700, while the actual RFC calls out using UDP port 3799.",
                reference = "https://www.cisco.com/c/en/us/support/docs/security-vpn/ipsec-negotiation-ike-protocols/14106-how-to-ipsec.html"
            ),
            Question.MultipleChoice(
                question = "Which public cloud provider supports the Cisco Next Generation Firewall Virtual?",
                options = listOf(
                    "A. Google Cloud Platform",
                    "B. Red Hat Enterprise Visualization",
                    "C. VMware ESXi",
                    "D. Amazon Web Services"
                ),
                correct = setOf("D"),
                explanation = "The Cisco NGFW virtual appliance is available in the AWS and Azure marketplaces. In AWS, it can be deployed in routed and passive modes. Passive mode design requires ERSPAN, the Encapsulated Remote Switched Port Analyzer, which is currently not available in Azure.",
                reference = "https://www.cisco.com/c/en/us/products/collateral/security/adaptive-security-virtual-appliance-asav/white-paper-c11-740505.html"
            ),
            Question.DragAndDrop(
                question = "Match the suspicious patterns for the Cisco Tetration platform with their correct definitions.",
                items = listOf(
                    "interesting file access",
                    "file access from a different user",
                    "user login suspicious behavior",
                    "privilege escalation"
                ),
                categories = listOf(
                    "Cisco Tetration platform can be armed to look at sensitive files",
                    "Cisco Tetration platform learns the normal behavior of which file is accessed by which user",
                    "Cisco Tetration platform watches user login failures and user login methods",
                    "Watches for privilege changes in the process lineage tree"
                ),
                correctMapping = mapOf(
                    "interesting file access" to "Cisco Tetration platform can be armed to look at sensitive files",
                    "file access from a different user" to "Cisco Tetration platform learns the normal behavior of which file is accessed by which user",
                    "user login suspicious behavior" to "Cisco Tetration platform watches user login failures and user login methods",
                    "privilege escalation" to "Watches for privilege changes in the process lineage tree"
                ),
                explanation = "Cisco Tetration platform studies the behavior of various processes and applications in the workload, measuring them against known bad behavior sequences. It factors in process hashes and understands clear definitions of these building blocks to watch for suspicious patterns including shell code execution, privilege escalation, side channel attacks, raw socket creation, user login behavior, file access patterns, and unseen commands.",
                reference = "https://www.cisco.com/c/en/us/products/collateral/data-center-analytics/tetration-analytics/white-paper-c11-740380.html"
            ),
            Question.MultipleChoice(
                question = "What is the purpose of the My Devices Portal in a Cisco ISE environment?",
                options = listOf(
                    "A. to register new laptops and mobile devices",
                    "B. to request a newly provisioned mobile device",
                    "C. to provision userless and agentless systems",
                    "D. to manage and deploy antivirus definitions and patches on systems owned by the end user"
                ),
                correct = setOf("A"),
                explanation = "Depending on your company policy, you might be able to use your mobile phones, tablets, printers, Internet radios, and other network devices on your company's network. You can use the My Devices portal to register and manage these devices on your company's network.",
                reference = "https://www.cisco.com/c/en/us/td/docs/security/ise/2-4/mydevices/b_mydevices_2x.html"
            ),
            Question.MultipleChoice(
                question = "Refer to the exhibit.\n\nip dhcp snooping\nip dhcp snooping vlan 41,44\n!\ninterface GigabitEthernet1/0/1\n description Uplink_To_Distro_Switch_g1/0/11\n switchport trunk native vlan 999\n switchport trunk allowed vlan 40,41,44\n switchport mode trunk\n\nAn organization is using DHCP Snooping within their network. A user on VLAN 41 on a new switch is complaining that an IP address is not being obtained. Which command should be configured on the switch interface in order to provide the user with network connectivity?",
                options = listOf(
                    "A. ip dhcp snooping verify mac-address",
                    "B. ip dhcp snooping limit 41",
                    "C. ip dhcp snooping vlan 41",
                    "D. ip dhcp snooping trust"
                ),
                correct = setOf("D"),
                explanation = "To understand DHCP snooping we need to learn about DHCP spoofing attack first. DHCP spoofing is a type of attack in that the attacker listens for DHCP Requests from clients and answers them with fake DHCP Response before the authorized DHCP Response comes to the clients. The fake DHCP Response often gives its IP address as the client default gateway -> all the traffic sent from the client will go through the attacker computer, the attacker becomes a \"man-in-the-middle\". DHCP snooping can prevent DHCP spoofing attacks. DHCP snooping is a Cisco Catalyst feature that determines which switch ports can respond to DHCP requests. Ports are identified as trusted and untrusted. Only ports that connect to an authorized DHCP server are trusted, and allowed to send all types of DHCP messages. All other ports on the switch are untrusted and can send only DHCP requests. If a DHCP response is seen on an untrusted port, the port is shut down. The port connected to a DHCP server should be configured as trusted port with the \"ip dhcp snooping trust\" command. Other ports connecting to hosts are untrusted ports by default.",
                reference = "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
            ),
            Question.MultipleChoice(
                question = "What is the purpose of the certificate signing request when adding a new certificate for a server?",
                options = listOf(
                    "A. It is the password for the certificate that is needed to install it with.",
                    "B. It provides the server information so a certificate can be created and signed",
                    "C. It provides the certificate client information so the server can authenticate against it when installing",
                    "D. It is the certificate that will be loaded onto the server"
                ),
                correct = setOf("B"),
                explanation = "A certificate signing request (CSR) is one of the first steps towards getting your own SSL Certificate. Generated on the same server you plan to install the certificate on, the CSR contains information (e.g. common name, organization, country) that the Certificate Authority (CA) will use to create your certificate. It also contains the public key that will be included in your certificate and is signed with the corresponding private key.",
                reference = "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
            ),
            Question.MultipleChoice(
                question = "What is the Cisco API-based broker that helps reduce compromises, application risks, and data breaches in an environment that is not on-premise?",
                options = listOf(
                    "A. Cisco Cloudlock",
                    "B. Cisco Umbrella",
                    "C. Cisco AMP",
                    "D. Cisco App Dynamics"
                ),
                correct = setOf("A"),
                explanation = "Cisco Cloudlock is a cloud-native cloud access security broker (CASB) that helps you move to the cloud safely. It protects your cloud users, data, and apps. Cisco Cloudlock provides visibility and compliance checks, protects data against misuse and exfiltration, and provides threat protections against malware like ransomware.",
                reference = "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
            ),
            Question.MultipleChoice(
                question = "What is managed by Cisco Security Manager?",
                options = listOf(
                    "A. access point",
                    "B. Secure Web Appliance",
                    "C. ASA",
                    "D. Secure Email Gateway"
                ),
                correct = setOf("C"),
                explanation = "Cisco Security Manager provides a comprehensive management solution for:\n- Cisco ASA 5500 Series Adaptive Security Appliances\n- Cisco intrusion prevention systems 4200 and 4500 Series Sensors\n- Cisco AnyConnect Secure Mobility Client",
                reference = "https://www.cisco.com/c/en/us/products/security/security-manager/index.html"
            ),
            Question.MultipleChoice(
                question = "How does Cisco Advanced Phishing Protection protect users?",
                options = listOf(
                    "A. It validates the sender by using DKIM.",
                    "B. It determines which identities are perceived by the sender",
                    "C. It utilizes sensors that send messages securely.",
                    "D. It uses machine learning and real-time behavior analytics."
                ),
                correct = setOf("D"),
                explanation = "Cisco Advanced Phishing Protection provides sender authentication and BEC detection capabilities. It uses advanced machine learning techniques, real-time behavior analytics, relationship modeling, and telemetry to protect against identity deception-based threats.",
                reference = "https://docs.ces.cisco.com/docs/advanced-phishing-protection"
            ),
            Question.MultipleChoice(
                question = "What is a benefit of using Cisco FMC over Cisco ASDM?",
                options = listOf(
                    "A. Cisco FMC uses Java while Cisco ASDM uses HTML5.",
                    "B. Cisco FMC provides centralized management while Cisco ASDM does not.",
                    "C. Cisco FMC supports pushing configurations to devices while Cisco ASDM does not.",
                    "D. Cisco FMC supports all firewall products whereas Cisco ASDM only supports Cisco ASA devices"
                ),
                correct = setOf("B"),
                explanation = "The Cisco Secure Firewall Threat Defense Manager (Firepower Management Center) increases the effectiveness of your Cisco network security solutions by providing centralized, integrated, and streamlined management.",
                reference = "https://www.cisco.com/c/en/us/products/collateral/security/firesight-management-center/datasheet-c78-736775.html"
            ),
            Question.MultipleChoice(
                question = "What is a key difference between Cisco Firepower and Cisco ASA?",
                options = listOf(
                    "A. Cisco ASA provides access control while Cisco Firepower does not.",
                    "B. Cisco Firepower provides identity-based access control while Cisco ASA does not.",
                    "C. Cisco Firepower natively provides intrusion prevention capabilities while Cisco ASA does not.",
                    "D. Cisco ASA provides SSL inspection while Cisco Firepower does not."
                ),
                correct = setOf("C"),
                explanation = "Cisco Firepower provides native intrusion prevention capabilities while Cisco ASA requires additional modules for this functionality.",
                reference = "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
            ),
            Question.MultipleChoice(
                question = "An organization is implementing URL blocking using Cisco Umbrella. The users are able to go to some sites but other sites are not accessible due to an error. Why is the error occurring?",
                options = listOf(
                    "A. Client computers do not have the Cisco Umbrella Root CA certificate installed.",
                    "B. IP-Layer Enforcement is not configured.",
                    "C. Client computers do not have an SSL certificate deployed from an internal CA server.",
                    "D. Intelligent proxy and SSL decryption is disabled in the policy."
                ),
                correct = setOf("A"),
                explanation = "Other features are dependent on SSL Decryption functionality, which requires the Cisco Umbrella root certificate. Having the SSL Decryption feature improves: Custom URL Blocking—Required to block the HTTPS version of a URL. Umbrella's Block Page and Block Page Bypass features present an SSL certificate to browsers that make connections to HTTPS sites. This SSL certificate matches the requested site but will be signed by the Cisco Umbrella certificate authority (CA). If the CA is not trusted by your browser, an error page may be displayed.",
                reference = "https://docs.umbrella.com/deployment-umbrella/docs/rebrand-cisco-certificate-import-information"
            ),
            Question.MultipleChoice(
                question = "Which two aspects of the cloud PaaS model are managed by the customer but not the provider? (Choose two)",
                options = listOf(
                    "A. virtualization",
                    "B. middleware",
                    "C. operating systems",
                    "D. applications",
                    "E. data"
                ),
                correct = setOf("D", "E"),
                explanation = "Customers must manage applications and data in PaaS.",
                reference = "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
            ),
            Question.MultipleChoice(
                question = "What is an attribute of the DevSecOps process?",
                options = listOf(
                    "A. mandated security controls and check lists",
                    "B. security scanning and theoretical vulnerabilities",
                    "C. development security",
                    "D. isolated security team"
                ),
                correct = setOf("C"),
                explanation = "DevSecOps (development, security, and operations) is a concept used in recent years to describe how to move security activities to the start of the development life cycle and have built-in security practices in the continuous integration/continuous deployment (CI/CD) pipeline. Thus minimizing vulnerabilities and bringing security closer to IT and business objectives.",
                reference = "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
            ),
            Question.MultipleChoice(
                question = "An engineer notices traffic interruption on the network. Upon further investigation, it is learned that broadcast packets have been flooding the network. What must be configured, based on a predefined threshold, to address this issue?",
                options = listOf(
                    "A. Bridge Protocol Data Unit guard",
                    "B. embedded event monitoring",
                    "C. storm control",
                    "D. access control lists"
                ),
                correct = setOf("C"),
                explanation = "Storm control prevents traffic on a LAN from being disrupted by a broadcast, multicast, or unicast storm on one of the physical interfaces. A LAN storm occurs when packets flood the LAN, creating excessive traffic and degrading network performance. Errors in the protocol-stack implementation, mistakes in network configurations, or users issuing a denial-of-service attack can cause a storm.",
                reference = "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
            ),
            Question.MultipleChoice(
                question = "Which two cryptographic algorithms are used with IPsec? (Choose two)",
                options = listOf(
                    "A. AES-BAC",
                    "B. AES-ABC",
                    "C. HMAC-SHA1/SHA2",
                    "D. Triple AMC-CBC",
                    "E. AES-CBC"
                ),
                correct = setOf("C", "E"),
                explanation = "Cryptographic algorithms defined for use with IPsec include:\n+ HMAC-SHA1/SHA2 for integrity protection and authenticity.\n+ TripleDES-CBC for confidentiality\n+ AES-CBC and AES-CTR for confidentiality.\n+ AES-GCM and ChaCha20-Poly1305 providing confidentiality and authentication together efficiently.",
                reference = "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
            )
        ))
    }

    // Get a batch of questions
    fun getQuestionsBatch(startIndex: Int = 0, count: Int = BATCH_SIZE): List<Question> {
        val endIndex = minOf(startIndex + count, allQuestions.size)
        return allQuestions.subList(startIndex, endIndex)
    }

    // Get total number of questions
    fun getTotalQuestions(): Int = allQuestions.size

    // Get a random batch of questions
    fun getRandomQuestions(count: Int = BATCH_SIZE): List<Question> {
        return allQuestions.shuffled().take(count)
    }

    // Get questions by category (if you want to add categories later)
    fun getQuestionsByCategory(category: String): List<Question> {
        return allQuestions.filter { question ->
            when (question) {
                is Question.MultipleChoice -> question.reference.contains(category, ignoreCase = true)
                is Question.DragAndDrop -> question.reference.contains(category, ignoreCase = true)
            }
        }
    }

    // Add a new question
    fun addQuestion(question: Question) {
        allQuestions.add(question)
    }

    // Add multiple questions
    fun addQuestions(questions: List<Question>) {
        allQuestions.addAll(questions)
    }

    // Clear all questions
    fun clearQuestions() {
        allQuestions.clear()
    }
} 