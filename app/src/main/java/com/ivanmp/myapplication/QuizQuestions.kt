package com.ivanmp.myapplication

import android.util.Log

object QuizQuestions {
    private val questionSets = mutableMapOf<QuestionCategory, MutableList<Question>>()
    private const val BATCH_SIZE = 100

    // Initialize questions
    init {
        // Initialize empty lists for each part
        QuestionCategory.values().forEach { category ->
            questionSets[category] = mutableListOf()
        }

        // Add all questions to SCOR_PART_1 for now
        questionSets[QuestionCategory.SCOR_PART_1]?.addAll(listOf(
            Question.DragAndDrop(
                question = "Drag and drop the capabilities of Cisco Firepower versus Cisco AMP from the left into the appropriate category on the right.",
                items = listOf(
                    "provides the ability to perform network discovery",
                    "provides detection, blocking, tracking, analyse and remediation to protect against targeted persistent malware attacks",
                    "provides intrusion prevention before malware comprises the host",
                    "provides superior threat prevention and mitigation for known and unknown threats",
                    "provides the root cause of a threat based on the indicators of compromise seen",
                    "provides outbreak control through custom detections"
                ),
                categories = listOf(
                    "Cisco Firepower",
                    "Cisco AMP"
                ),
                correctMapping = mapOf(
                    "provides the ability to perform network discovery" to "Cisco Firepower",
                    "provides detection, blocking, tracking, analyse and remediation to protect against targeted persistent malware attacks" to "Cisco AMP",
                    "provides intrusion prevention before malware comprises the host" to "Cisco Firepower",
                    "provides superior threat prevention and mitigation for known and unknown threats" to "Cisco Firepower",
                    "provides the root cause of a threat based on the indicators of compromise seen" to "Cisco AMP",
                    "provides outbreak control through custom detections" to "Cisco AMP"
                ),
                explanation = """The Firepower System uses network discovery and identity policies to collect host, application, and user data for traffic on your network. You can use certain types of discovery and identity data to build a comprehensive map of your network assets, perform forensic analysis, behavioral profiling, access control, and mitigate and respond to the vulnerabilities and exploits to which your organization is susceptible.

The Cisco Advanced Malware Protection (AMP) solution enables you to detect and block malware, continuously analyze for malware, and get retrospective alerts. AMP for Networks delivers network-based advanced malware protection that goes beyond point-in-time detection to protect your organization across the entire attack continuum – before, during, and after an attack. Designed for Cisco Firepower network threat appliances, AMP for Networks detects, blocks, tracks, and contains malware threats across multiple threat vectors within a single system. It also provides the visibility and control necessary to protect your organization against highly sophisticated, targeted, zero‑day, and persistent advanced malware threats.

Note:
Before an attack, AMP uses global threat intelligence from Cisco's Talos Security Intelligence and Research Group and Threat Grid's threat intelligence feeds to strengthen defenses and protect against known and emerging threats.

Detecting targeted, persistent malware attacks is a bigger problem than a single point-in-time control or product can effectively address on its own. Advanced malware protection requires an integrated set of controls and a continuous process to detect, confirm, track, analyze, and remediate these threats – before, during, and after an attack.""",
                reference = "https://www.cisco.com/c/dam/global/shared/assets/pdf/sc/sec_amp_guide_cte_env_etmg_en.pdf",
                category = QuestionCategory.SCOR_PART_1
            ),
            Question.DragAndDrop(
                question = "Drag and drop the suspicious patterns for the Cisco Tetration platform from the left onto the correct definitions on the right.",
                items = listOf(
                    "interesting file access",
                    "file access from a different user",
                    "user login suspicious behavior",
                    "privilege escalation"
                ),
                categories = listOf(
                    "Cisco Tetration platform can be armed to look at sensitive files",
                    "Watches for privilege changes in the process lineage tree",
                    "Cisco Tetration platform watches user login failures and user login methods",
                    "Cisco Tetration platform learns the normal behavior of which file is accessed by which user"
                ),
                correctMapping = mapOf(
                    "interesting file access" to "Cisco Tetration platform can be armed to look at sensitive files",
                    "privilege escalation" to "Watches for privilege changes in the process lineage tree",
                    "user login suspicious behavior" to "Cisco Tetration platform watches user login failures and user login methods",
                    "file access from a different user" to "Cisco Tetration platform learns the normal behavior of which file is accessed by which user"
                ),
                explanation = """Cisco Tetration platform studies the behavior of the various processes and applications in the workload, measuring them against known bad behavior sequences. It also factors in the process hashes it collects. By studying various sets of malwares, the Tetration Analytics engineering team deconstructed it back into its basic building blocks. Therefore, the platform understands clear and crisp definitions of these building blocks and watches for them.

The various suspicious patterns for which the Cisco Tetration platform looks in the current release are:
+ Shell code execution: Looks for the patterns used by shell code.
+ Privilege escalation: Watches for privilege changes from a lower privilege to a higher privilege in the process lineage tree.
+ Side channel attacks: Cisco Tetration platform watches for cache-timing attacks and page table fault bursts. Using these, it can detect Meltdown, Spectre, and other cache-timing attacks.
+ Raw socket creation: Creation of a raw socket by a nonstandard process (for example, ping).
+ User login suspicious behavior: Cisco Tetration platform watches user login failures and user login methods.
+ Interesting file access: Cisco Tetration platform can be armed to look at sensitive files.
+ File access from a different user: Cisco Tetration platform learns the normal behavior of which file is accessed by which user.
+ Unseen command: Cisco Tetration platform learns the behavior and set of commands as well as the lineage of each command over time. Any new command or command with a different lineage triggers the interest of the Tetration Analytics platform.""",
                reference = "https://www.cisco.com/c/en/us/products/collateral/data-center-analytics/tetration-analytics/white-paper-c11-740380.html",
                category = QuestionCategory.SCOR_PART_1
            ),
            Question.DragAndDrop(
                question = "Drag and drop the descriptions from the left onto the encryption algorithms on the right.",
                items = listOf(
                    "requires more time",
                    "requires secret keys",
                    "3DES",
                    "Diffie-Hellman exchange"
                ),
                categories = listOf(
                    "Asymmetric",
                    "Symmetric"
                ),
                correctMapping = mapOf(
                    "requires more time" to "Asymmetric",
                    "requires secret keys" to "Symmetric",
                    "3DES" to "Symmetric",
                    "Diffie-Hellman exchange" to "Asymmetric"
                ),
                explanation = """Symmetric encryption uses a single key that needs to be shared among the people who need to receive the message while asymmetric encryption uses a pair of public key and a private key to encrypt and decrypt messages when communicating.

Asymmetric encryption takes relatively more time than the symmetric encryption.

Diffie Hellman algorithm is an asymmetric algorithm used to establish a shared secret for a symmetric key algorithm. Nowadays most of the people uses hybrid crypto system i.e, combination of symmetric and asymmetric encryption. Asymmetric Encryption is used as a technique in key exchange mechanism to share secret key and after the key is shared between sender and receiver, the communication will take place using symmetric encryption. The shared secret key will be used to encrypt the communication.

Triple DES (3DES), a symmetric-key algorithm for the encryption of electronic data, is the successor of DES (Data Encryption Standard) and provides more secure encryption then DES.

Note: Although "requires secret keys" option in this question is a bit unclear but it can only be assigned to Symmetric algorithm.""",
                reference = "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                category = QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "What is a characteristic of a bridge group in ASA Firewall transparent mode?",
                listOf(
                    "A. It includes multiple interfaces and access rules between interfaces are customizable",
                    "B. It is a Layer 3 segment and includes one port and customizable access rules",
                    "C. It allows ARP traffic with a single access rule",
                    "D. It has an IP address on its BVI interface and is used for management traffic"
                ),
                setOf("A"),
                "A bridge group is a group of interfaces that the ASA bridges instead of routes. Bridge groups are only supported in Transparent Firewall Mode. Like any other firewall interfaces, access control between interfaces is controlled, and all of the usual firewall checks are in place.\n\nEach bridge group includes a Bridge Virtual Interface (BVI). The ASA uses the BVI IP address as the source address for packets originating from the bridge group. The BVI IP address must be on the same subnet as the bridge group member interfaces. The BVI does not support traffic on secondary networks; only traffic on the same network as the BVI IP address is supported.\n\nYou can include multiple interfaces per bridge group. If you use more than 2 interfaces per bridge group, you can control communication between multiple segments on the same network, and not just between inside and outside. For example, if you have three inside segments that you do not want to communicate with each other, you can put each segment on a separate interface, and only allow them to communicate with the outside interface. Or you can customize the access rules between interfaces to allow only as much access as desired.",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa95/configuration/general/asa-95-general-config/intro-fw.html",
                QuestionCategory.SCOR_PART_1
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
                "Vendors, security researchers, and vulnerability coordination centers typically assign vulnerabilities an identifier that's disclosed to the public. This identifier is known as the Common Vulnerabilities and Exposures (CVE). CVE is an industry-wide standard. CVE is sponsored by US-CERT, the office of Cybersecurity and Communications at the U.S. Department of Homeland Security.\n\nThe goal of CVE is to make it's easier to share data across tools, vulnerability repositories, and security services.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                QuestionCategory.SCOR_PART_1
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
                "Cisco standard NetFlow version 5 defines a flow as a unidirectional sequence of packets that all share seven values which define a unique key for the flow:\n+ Ingress interface (SNMP ifIndex)\n+ Source IP address\n+ Destination IP address\n+ IP protocol\n+ Source port for UDP or TCP, 0 for other protocols\n+ Destination port for UDP or TCP, type and code for ICMP, or 0 for other protocols\n+ IP Type of Service\n\nNote: A flow is a unidirectional series of packets between a given source and destination.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "What provides the ability to program and monitor networks from somewhere other than the DNAC GUI?",
                listOf(
                    "A. NetFlow",
                    "B. desktop client",
                    "C. ASDM",
                    "D. API"
                ),
                setOf("D"),
                "APIs enable network management and monitoring programmatically outside the default DNAC GUI environment.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                QuestionCategory.SCOR_PART_1
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
                "SQL injection vulnerabilities allow attackers to insert malicious commands into the database, which would affect Machine 1 but not Machine 2 since it's only vulnerable to buffer overflows.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                QuestionCategory.SCOR_PART_1
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
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                QuestionCategory.SCOR_PART_1
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
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "An engineer is trying to securely connect to a router and wants to prevent insecure algorithms from being used. However, the connection is failing. Which action should be taken to accomplish this goal?",
                listOf(
                    "A. Disable telnet using the no ip telnet command.",
                    "B. Enable the SSH server using the ip ssh server command.",
                    "C. Configure the port using the ip ssh port 22 command.",
                    "D. Generate the RSA key using the crypto key generate rsa command."
                ),
                setOf("D"),
                "In this question, the engineer was trying to secure the connection so maybe he was trying to allow SSH to the device. But maybe something went wrong so the connection was failing (the connection used to be good). So maybe he was missing the \"crypto key generate rsa\" command.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "A network administrator is using the Cisco Secure Email Gateway with AMP to upload files to the cloud for analysis. The network is congested and is affecting communication. How will the Cisco Secure Email Gateway handle any files which need analysis?",
                listOf(
                    "A. AMP calculates the SHA-256 fingerprint, caches it, and periodically attempts the upload.",
                    "B. The file is queued for upload when connectivity is restored.",
                    "C. The file upload is abandoned.",
                    "D. The Secure Email Gateway immediately makes another attempt to upload the file."
                ),
                setOf("C"),
                "The appliance will try once to upload the file; if upload is not successful, for example because of connectivity problems, the file may not be uploaded. If the failure was because the file analysis server was overloaded, the upload will be attempted once more.\n\nIn this question, it stated \"the network is congested\" (not the file analysis server was overloaded) so the appliance will not try to upload the file again.",
                "https://www.cisco.com/c/en/us/support/docs/security/email-security-appliance/118796-technote-esa-00.html",
                QuestionCategory.SCOR_PART_1
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
                "SHA (Secure Hash Algorithm) provides the highest level of protection against brute-force attacks among the given options.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                QuestionCategory.SCOR_PART_1
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
                "Cisco ISE allows a global configuration to issue a Change of Authorization (CoA) in the Profiler Configuration page that enables the profiling service with more control over endpoints that are already authenticated.\n\nOne of the settings to configure the CoA type is \"Reauth\". This option is used to enforce reauthentication of an already authenticated endpoint when it is profiled.",
                "https://www.cisco.com/c/en/us/td/docs/security/ise/1-3/admin_guide/b_ise_admin_guide_13/b_ise_admin_guide_sample_chapter_010101.html",
                QuestionCategory.SCOR_PART_1
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
                "To block certain URLs in the \"Chat and Instant Messaging\" category, we need to choose URL Reputation from 6 to 10.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                QuestionCategory.SCOR_PART_1
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
                "https://talosintelligence.com/newsletters",
                QuestionCategory.SCOR_PART_1
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
                "Cisco Intercloud Fabric addresses the cloud deployment requirements appropriate for two hybrid cloud deployment models: Enterprise Managed (an enterprise manages its own cloud environments) and Service Provider Managed (the service provider administers and controls all cloud resources).\n\nThe Cisco Intercloud Fabric architecture provides two product configurations to address the following two consumption models:\n+ Cisco Intercloud Fabric for Business\n+ Cisco Intercloud Fabric for Providers",
                "https://www.cisco.com/c/en/us/td/docs/solutions/Hybrid_Cloud/Intercloud/Intercloud_Fabric.pdf",
                QuestionCategory.SCOR_PART_1
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
                "While DDoS offer a less complicated attack mode than other forms of cyberattacks, they are growing stronger and more sophisticated. There are three basic categories of attack:\n+ volume-based attacks, which use high traffic to inundate the network bandwidth\n+ protocol attacks, which focus on exploiting server resources\n+ application attacks, which focus on web applications and are considered the most sophisticated and serious type of attacks",
                "https://www.esecurityplanet.com/networks/types-of-ddos-attacks/",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "Refer to the exhibit.\n\nWhich type of authentication is in use?",
                listOf(
                    "A. LDAP authentication for Microsoft Outlook",
                    "B. POP3 authentication",
                    "C. SMTP relay server authentication",
                    "D. external user and relay mail authentication"
                ),
                setOf("D"),
                """The TLS connections are recorded in the mail logs, along with other significant actions that are related to messages, such as filter actions, anti-virus and anti-spam verdicts, and delivery attempts. If there is a successful TLS connection, there will be a TLS success entry in the mail logs. Likewise, a failed TLS connection produces a TLS failed entry. If a message does not have an associated TLS entry in the log file, that message was not delivered over a TLS connection.

The exhibit shows a successful TLS connection from the remote host (reception) in the mail log.""",
                "https://www.cisco.com/c/en/us/support/docs/security/email-security-appliance/118844-technote-esa-00.html",
                QuestionCategory.SCOR_PART_1,
                "smtp_auth_logs"
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
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                QuestionCategory.SCOR_PART_1
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
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "What are two differences between a Cisco WSA that is running in transparent mode and one running in explicit mode? (Choose two)",
                listOf(
                    "A. When the Cisco WSA is running in transparent mode, it uses the WSA's own IP address as the HTTP request destination.",
                    "B. The Cisco WSA responds with its own IP address only if it is running in explicit mode.",
                    "C. The Cisco WSA is configured in a web browser only if it is running in transparent mode.",
                    "D. The Cisco WSA uses a Layer 3 device to redirect traffic only if it is running in transparent mode.",
                    "E. The Cisco WSA responds with its own IP address only if it is running in transparent mode."
                ),
                setOf("B", "D"),
                "The Cisco Web Security Appliance (WSA) includes a web proxy, a threat analytics engine, antimalware engine, policy management, and reporting in a single physical or virtual appliance. The main use of the Cisco WSA is to protect users from accessing malicious websites and being infected by malware.\n\nYou can deploy the Cisco WSA in two different modes:\n– Explicit forward mode\n– Transparent mode\n\nIn explicit forward mode, the client is configured to explicitly use the proxy, subsequently sending all web traffic to the proxy. Because the client knows there is a proxy and sends all traffic to the proxy in explicit forward mode, the client does not perform a DNS lookup of the domain before requesting the URL. The Cisco WSA is responsible for DNS resolution, as well.\n\nWhen you configure the Cisco WSA in explicit mode, you do not need to configure any other network infrastructure devices to redirect client requests to the Cisco WSA. However, you must configure each client to send traffic to the Cisco WSA.\n\nWhen the Cisco WSA is in transparent mode, clients do not know there is a proxy deployed. Network infrastructure devices are configured to forward traffic to the Cisco WSA. In transparent mode deployments, network infrastructure devices redirect web traffic to the proxy. Web traffic redirection can be done using policy-based routing (PBR)—available on many routers —or using Cisco's Web Cache Communication Protocol (WCCP) on Cisco ASA, Cisco routers, or switches.",
                "https://www.cisco.com/c/en/us/tech/content-networking/web-cache-communications-protocol-wccp/index.html",
                QuestionCategory.SCOR_PART_1
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
                "URL conditions in access control rules allow you to limit the websites that users on your network can access. This feature is called URL filtering. There are two ways you can use access control to specify URLs you want to block (or, conversely, allow):\n– With any license, you can manually specify individual URLs, groups of URLs, and URL lists and feeds to achieve granular, custom control over web traffic.\n– With a URL Filtering license, you can also control access to websites based on the URL's general classification, or category, and risk level, or reputation. The system displays this category and reputation data in connection logs, intrusion events, and application details.",
                "https://www.cisco.com/c/en/us/td/docs/security/firepower/60/configuration/guide/fpmc-config-guide-v60/Access_Control_Rules__URL_Filtering.html",
                QuestionCategory.SCOR_PART_1
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
                "https://www.ciscopress.com/articles/article.asp?p=3004581&seqNum=2",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "An attacker needs to perform reconnaissance on a target system to help gain access to it. The system has weak passwords, no encryption on the VPN links, and software bugs on the system's applications. Which vulnerability allows the attacker to see the passwords being transmitted in clear text?",
                listOf(
                    "A. weak passwords for authentication",
                    "B. unencrypted links for traffic",
                    "C. software bugs on applications",
                    "D. improper file security"
                ),
                setOf("B"),
                "Unencrypted links for traffic allow attackers to see passwords being transmitted in clear text.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "Using Cisco Firepower's Security Intelligence policies, upon which two criteria is Firepower block based? (Choose two)",
                listOf(
                    "A. URLs",
                    "B. protocol IDs",
                    "C. IP addresses",
                    "D. MAC addresses",
                    "E. port numbers"
                ),
                setOf("A", "C"),
                "Security Intelligence Sources\n…\nCustom Block lists or feeds (or objects or groups)\nBlock specific IP addresses, URLs, or domain names using a manually-created list or feed (for IP addresses, you can also use network objects or groups.)\nFor example, if you become aware of malicious sites or addresses that are not yet blocked by a feed, add these sites to a custom Security Intelligence list and add this custom list to the Block list in the Security Intelligence tab of your access control policy.",
                "https://www.cisco.com/c/en/us/td/docs/security/firepower/623/configuration/guide/fpmc-config-guide-v623/security_intelligence_blacklisting.html",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "Which Cisco platform ensures that machines that connect to organizational networks have the recommended antivirus definitions and patches to help prevent an organizational malware outbreak?",
                listOf(
                    "A. Cisco WiSM",
                    "B. Cisco Secure Email Gateway",
                    "C. Cisco ISE",
                    "D. Cisco Prime Infrastructure"
                ),
                setOf("C"),
                "A posture policy is a collection of posture requirements, which are associated with one or more identity groups, and operating systems. We can configure ISE to check for the Windows patch at Work Centers > Posture > Posture Elements > Conditions > File.\nIn this example, we are going to use the predefined file check to ensure that our Windows 10 clients have the critical security patch installed to prevent the Wanna Cry malware; and we can also configure ISE to update the client with this patch.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "What are two benefits of Flexible NetFlow records? (Choose two)",
                listOf(
                    "A. They allow the user to configure flow information to perform customized traffic identification",
                    "B. They provide attack prevention by dropping the traffic",
                    "C. They provide accounting and billing enhancements",
                    "D. They converge multiple accounting technologies into one accounting mechanism",
                    "E. They provide monitoring of a wider range of IP packet information from Layer 2 to 4"
                ),
                setOf("A", "D"),
                "Key Advantages to using Flexible NetFlow:\n+ Flexibility, scalability of flow data beyond traditional NetFlow\n+ The ability to monitor a wider range of packet information producing new information about network behavior not available today\n+ Enhanced network anomaly and security detection\n+ User configurable flow information to perform customized traffic identification and the ability to focus and monitor specific network behavior (-> Therefore answer A is correct)\n+ Convergence of multiple accounting technologies into one accounting mechanism (-> Therefore answer D is correct)\nFlexible NetFlow is integral part of Cisco IOS Software that collects and measures data allowing all routers or switches in the network to become a source of telemetry and a monitoring device. Flexible NetFlow allows extremely granular and accurate traffic measurements and high-level aggregated traffic collection. Because it is part of Cisco IOS Software, Flexible NetFlow enables Cisco product-based networks to perform traffic flow analysis without purchasing external probes–making traffic analysis economical on large IP networks.",
                "https://www.cisco.com/c/en/us/products/collateral/ios-nx-os-software/flexible-netflow/product_data_sheet0900aecd804b590b.html",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "How does DNS Tunneling exfiltrate data?",
                listOf(
                    "A. An attacker registers a domain that a client connects to based on DNS records and sends malware through that connection.",
                    "B. An attacker opens a reverse DNS shell to get into the client's system and install malware on it.",
                    "C. An attacker uses a non-standard DNS port to gain access to the organization's DNS servers in order to poison the resolutions.",
                    "D. An attacker sends an email to the target with hidden DNS resolvers in it to redirect them to a malicious domain."
                ),
                setOf("A"),
                "DNS tunneling is a method of data exfiltration that encodes the data of other programs or protocols in DNS queries and responses. DNS tunneling often includes data payloads that can be added to an otherwise legitimate DNS query. As an alternative, entire data streams can be covertly carried over DNS.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "A user has a device in the network that is receiving too many connection requests from multiple machines. Which type of attack is the device undergoing?",
                listOf(
                    "A. phishing",
                    "B. slowloris",
                    "C. pharming",
                    "D. SYN flood"
                ),
                setOf("D"),
                "A SYN flood is a form of denial-of-service attack in which an attacker sends a succession of SYN requests to a target's system in an attempt to consume enough server resources to make the system unresponsive to legitimate traffic.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "An organization is receiving SPAM emails from a known malicious domain. What must be configured in order to prevent the session during the initial TCP communication?",
                listOf(
                    "A. Configure the Cisco Secure Email Gateway to drop the malicious emails",
                    "B. Configure policies to quarantine malicious emails",
                    "C. Configure policies to stop and reject communication",
                    "D. Configure the Cisco Secure Email Gateway to reset the TCP connection"
                ),
                setOf("C"),
                "Each Mail Flow Policy has an access rule, such as ACCEPT, REJECT, RELAY, CONTINUE, and TCPREFUSE. A host that attempts to establish a connection to your Secure Email Gateway and matches a Sender Group using a TCPREFUSE access rule is not allowed to connect to your Secure Email Gateway. From the standpoint of the sending server, it will appear as if your server is unavailable. Most Mail Transfer Agents (MTAs) will retry frequently in this case, which will create more traffic then answering once with a clear hard bounce, for example, REJECT.\nA host that attempts to establish a connection to your Secure Email Gateway and encounters a REJECT will receive a 554 SMTP error (hard bounce).",
                "https://www.cisco.com/c/en/us/support/docs/security/email-security-appliance/118007-configure-esa-00.html",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "A Cisco Firepower administrator needs to configure a rule to allow a new application that has never been seen on the network. Which two actions should be selected to allow the traffic to pass without inspection? (Choose two)",
                listOf(
                    "A. permit",
                    "B. trust",
                    "C. reset",
                    "D. allow",
                    "E. monitor"
                ),
                setOf("B", "D"),
                "Each rule also has an action, which determines whether you monitor, trust, block, or allow matching traffic.\nNote: With action \"trust\", Firepower does not do any more inspection on the traffic. There will be no intrusion protection and also no file-policy on this traffic.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "An engineer needs behavioral analysis to detect malicious activity on the hosts, and is configuring the organization's public cloud to send telemetry using the cloud provider's mechanisms to a security device. Which mechanism should the engineer configure to accomplish this goal?",
                listOf(
                    "A. mirror port",
                    "B. sFlow",
                    "C. NetFlow",
                    "D. VPC flow logs"
                ),
                setOf("D"),
                "When you operate your own switches and routers, you have tools like mirror ports and NetFlow data, which can be used to analyze overall security and performance. In a cloud environment, these options have not been available.\nNow there's a new option for Amazon Web Services (AWS) customers who operate virtual private cloud (VPC) networks. AWS recently introduced VPC Flow Logs, which facilitate logging of all the IP traffic to, from, and across your network. These logs are stored as records in special Amazon CloudWatch log groups and provide the same kind of information as NetFlow data.",
                "https://www.cisco.com/c/en/us/products/collateral/security/stealthwatch-cloud/at-a-glance-c45-739851.html",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "An engineer has enabled LDAP accept queries on a listener. Malicious actors must be prevented from quickly identifying all valid recipients. What must be done on the Cisco Secure Email Gateway to accomplish this goal?",
                listOf(
                    "A. Configure incoming content filters",
                    "B. Use Bounce Verification",
                    "C. Configure Directory Harvest Attack Prevention",
                    "D. Bypass LDAP access queries in the recipient access table"
                ),
                setOf("C"),
                "A Directory Harvest Attack (DHA) is a technique used by spammers to find valid/existent email addresses at a domain either by using Brute force or by guessing valid e-mail addresses at a domain using different permutations of common username. Its easy for attackers to get hold of a valid email address if your organization uses standard format for official e-mail alias (for example: jsmith@example.com). We can configure DHA Prevention to prevent malicious actors from quickly identifying valid recipients.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "What is a feature of Cisco NetFlow Secure Event Logging for Cisco ASAs?",
                listOf(
                    "A. Multiple NetFlow collectors are supported",
                    "B. Advanced NetFlow v9 templates and legacy v5 formatting are supported",
                    "C. Secure NetFlow connections are optimized for Cisco Prime Infrastructure",
                    "D. Flow-create events are delayed"
                ),
                setOf("D"),
                "The ASA and ASASM implementations of NetFlow Secure Event Logging (NSEL) provide the following major functions:\n…\n– Delays the export of flow-create events.",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa92/configuration/general/asa-general-cli/monitor-nsel.pdf",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "An engineer is configuring 802.1X authentication on Cisco switches in the network and is using CoA as a mechanism. Which port on the firewall must be opened to allow the CoA traffic to traverse the network?",
                listOf(
                    "A. TCP 6514",
                    "B. UDP 1700",
                    "C. TCP 49",
                    "D. UDP 1812"
                ),
                setOf("B"),
                "CoA Messages are sent on two different udp ports depending on the platform. Cisco standardizes on UDP port 1700, while the actual RFC calls out using UDP port 3799.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "Which public cloud provider supports the Cisco Next Generation Firewall Virtual?",
                listOf(
                    "A. Google Cloud Platform",
                    "B. Red Hat Enterprise Visualization",
                    "C. VMware ESXi",
                    "D. Amazon Web Services"
                ),
                setOf("D"),
                "Cisco Firepower NGFW Virtual (NGFWv) is the virtualized version of Cisco's Firepower next generation firewall.\nThe Cisco NGFW virtual appliance is available in the AWS and Azure marketplaces. In AWS, it can be deployed in routed and passive modes. Passive mode design requires ERSPAN, the Encapsulated Remote Switched Port Analyzer, which is currently not available in Azure.\nIn passive mode, NGFWv inspects packets like an Intrusion Detection System (IDS) appliance, but no action can be taken on the packet.\nIn routed mode NGFWv acts as a next hop for workloads. It can inspect packets and also take action on the packet based on rule and policy definitions.",
                "https://www.cisco.com/c/en/us/products/collateral/security/adaptive-security-virtual-appliance-asav/white-paper-c11-740505.html",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "What is the purpose of the My Devices Portal in a Cisco ISE environment?",
                listOf(
                    "A. to register new laptops and mobile devices",
                    "B. to request a newly provisioned mobile device",
                    "C. to provision userless and agentless systems",
                    "D. to manage and deploy antivirus definitions and patches on systems owned by the end user"
                ),
                setOf("A"),
                "Depending on your company policy, you might be able to use your mobile phones, tablets, printers, Internet radios, and other network devices on your company's network. You can use the My Devices portal to register and manage these devices on your company's network.",
                "https://www.cisco.com/c/en/us/td/docs/security/ise/2-4/mydevices/b_mydevices_2x.html",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "What is the purpose of the certificate signing request when adding a new certificate for a server?",
                listOf(
                    "A. It is the password for the certificate that is needed to install it with.",
                    "B. It provides the server information so a certificate can be created and signed",
                    "C. It provides the certificate client information so the server can authenticate against it when installing",
                    "D. It is the certificate that will be loaded onto the server"
                ),
                setOf("B"),
                "A certificate signing request (CSR) is one of the first steps towards getting your own SSL Certificate. Generated on the same server you plan to install the certificate on, the CSR contains information (e.g. common name, organization, country) that the Certificate Authority (CA) will use to create your certificate. It also contains the public key that will be included in your certificate and is signed with the corresponding private key.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "What is the Cisco API-based broker that helps reduce compromises, application risks, and data breaches in an environment that is not on-premise?",
                listOf(
                    "A. Cisco Cloudlock",
                    "B. Cisco Umbrella",
                    "C. Cisco AMP",
                    "D. Cisco App Dynamics"
                ),
                setOf("A"),
                "Cisco Cloudlock is a cloud-native cloud access security broker (CASB) that helps you move to the cloud safely. It protects your cloud users, data, and apps. Cisco Cloudlock provides visibility and compliance checks, protects data against misuse and exfiltration, and provides threat protections against malware like ransomware.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "What is the purpose of the Cisco Identity Services Engine (ISE) in a network environment?",
                listOf(
                    "A. to provide network access control and policy enforcement",
                    "B. to manage firewall rules and policies",
                    "C. to handle email security and spam filtering",
                    "D. to perform network traffic analysis"
                ),
                setOf("A"),
                "Cisco Identity Services Engine (ISE) is a network access control and policy enforcement platform that enables organizations to enforce compliance, enhance infrastructure security, and streamline service operations. It provides secure access to network resources for any device or user, anywhere in the world.",
                "https://www.cisco.com/c/en/us/products/security/identity-services-engine/index.html",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "Which Cisco security solution provides advanced malware protection and threat detection?",
                listOf(
                    "A. Cisco AMP (Advanced Malware Protection)",
                    "B. Cisco ISE",
                    "C. Cisco Umbrella",
                    "D. Cisco Firepower"
                ),
                setOf("A"),
                "Cisco Advanced Malware Protection (AMP) provides comprehensive malware protection that goes beyond point-in-time detection to protect your organization across the entire attack continuum – before, during, and after an attack. It uses global threat intelligence, advanced sandboxing, and machine learning to detect and block malware threats.",
                "https://www.cisco.com/c/en/us/products/security/advanced-malware-protection/index.html",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "What is the primary function of Cisco Umbrella?",
                listOf(
                    "A. to provide secure remote access to corporate networks",
                    "B. to protect against DNS-based threats and provide secure internet access",
                    "C. to manage network access control policies",
                    "D. to perform network traffic analysis"
                ),
                setOf("B"),
                "Cisco Umbrella provides secure internet access everywhere by combining multiple security functions into one solution. It protects against threats on the internet by blocking malicious domains, IPs, and URLs before a connection is even established. It also provides secure web gateway, firewall, and cloud access security broker (CASB) capabilities.",
                "https://www.cisco.com/c/en/us/products/security/umbrella/index.html",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "What is the purpose of Cisco Firepower Threat Defense (FTD)?",
                listOf(
                    "A. to provide email security and spam filtering",
                    "B. to manage network access control policies",
                    "C. to provide next-generation firewall capabilities with advanced threat protection",
                    "D. to perform network traffic analysis"
                ),
                setOf("C"),
                "Cisco Firepower Threat Defense (FTD) is a unified software image that combines Cisco ASA firewall capabilities with next-generation firewall features, including advanced threat protection. It provides comprehensive network security with application visibility and control, threat prevention, and malware protection.",
                "https://www.cisco.com/c/en/us/products/security/firepower-threat-defense/index.html",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "Which Cisco security solution provides secure remote access to corporate networks?",
                listOf(
                    "A. Cisco AnyConnect",
                    "B. Cisco ISE",
                    "C. Cisco Umbrella",
                    "D. Cisco Firepower"
                ),
                setOf("A"),
                "Cisco AnyConnect is a VPN client that provides secure remote access to corporate networks. It offers a seamless, always-on connection that protects users and data with features like split tunneling, endpoint security assessment, and secure mobility.",
                "https://www.cisco.com/c/en/us/products/security/anyconnect-secure-mobility-client/index.html",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "What is the purpose of Cisco Stealthwatch?",
                listOf(
                    "A. to provide email security and spam filtering",
                    "B. to manage network access control policies",
                    "C. to provide network visibility and threat detection",
                    "D. to perform network traffic analysis"
                ),
                setOf("C"),
                "Cisco Stealthwatch provides network visibility and threat detection by analyzing network traffic patterns. It uses machine learning and behavioral modeling to identify potential threats and security incidents, helping organizations detect and respond to security breaches more effectively.",
                "https://www.cisco.com/c/en/us/products/security/stealthwatch/index.html",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "What is the purpose of Cisco Email Security Appliance (ESA)?",
                listOf(
                    "A. to provide network access control and policy enforcement",
                    "B. to manage firewall rules and policies",
                    "C. to protect against email-borne threats and spam",
                    "D. to perform network traffic analysis"
                ),
                setOf("C"),
                "Cisco Email Security Appliance (ESA) provides comprehensive email security to protect organizations from email-borne threats, including spam, malware, phishing, and data loss. It uses advanced threat protection and content filtering to secure email communications.",
                "https://www.cisco.com/c/en/us/products/security/email-security-appliance/index.html",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "Which Cisco security solution provides web security and protection against web-based threats?",
                listOf(
                    "A. Cisco Web Security Appliance (WSA)",
                    "B. Cisco ISE",
                    "C. Cisco Umbrella",
                    "D. Cisco Firepower"
                ),
                setOf("A"),
                "Cisco Web Security Appliance (WSA) provides comprehensive web security to protect organizations from web-based threats. It offers URL filtering, malware protection, application visibility and control, and data loss prevention capabilities.",
                "https://www.cisco.com/c/en/us/products/security/web-security-appliance/index.html",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "What is the purpose of Cisco Cloud Email Security?",
                listOf(
                    "A. to provide network access control and policy enforcement",
                    "B. to manage firewall rules and policies",
                    "C. to protect against email-borne threats in cloud environments",
                    "D. to perform network traffic analysis"
                ),
                setOf("C"),
                "Cisco Cloud Email Security provides cloud-based email security to protect organizations from email-borne threats. It offers advanced threat protection, spam filtering, and data loss prevention capabilities, helping organizations secure their email communications in cloud environments.",
                "https://www.cisco.com/c/en/us/products/security/cloud-email-security/index.html",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "What is the purpose of Cisco Cloud Web Security?",
                listOf(
                    "A. to provide network access control and policy enforcement",
                    "B. to manage firewall rules and policies",
                    "C. to protect against web-based threats in cloud environments",
                    "D. to perform network traffic analysis"
                ),
                setOf("C"),
                "Cisco Cloud Web Security provides cloud-based web security to protect organizations from web-based threats. It offers URL filtering, malware protection, application visibility and control, and data loss prevention capabilities, helping organizations secure their web traffic in cloud environments.",
                "https://www.cisco.com/c/en/us/products/security/cloud-web-security/index.html",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "Which Cisco security solution provides secure access to cloud applications?",
                listOf(
                    "A. Cisco Cloud Access Security Broker (CASB)",
                    "B. Cisco ISE",
                    "C. Cisco Umbrella",
                    "D. Cisco Firepower"
                ),
                setOf("A"),
                "Cisco Cloud Access Security Broker (CASB) provides secure access to cloud applications by offering visibility, compliance, data security, and threat protection for cloud services. It helps organizations secure their cloud usage and protect sensitive data.",
                "https://www.cisco.com/c/en/us/products/security/cloud-access-security-broker/index.html",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "What is the purpose of Cisco Cloudlock?",
                listOf(
                    "A. to provide network access control and policy enforcement",
                    "B. to manage firewall rules and policies",
                    "C. to protect data and applications in cloud environments",
                    "D. to perform network traffic analysis"
                ),
                setOf("C"),
                "Cisco Cloudlock provides data and application security in cloud environments. It offers data loss prevention, user behavior analytics, and compliance monitoring capabilities, helping organizations protect their sensitive data and applications in the cloud.",
                "https://www.cisco.com/c/en/us/products/security/cloudlock/index.html",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "What is the purpose of Cisco Cloudlock for Google Workspace?",
                listOf(
                    "A. to provide network access control and policy enforcement",
                    "B. to manage firewall rules and policies",
                    "C. to protect data and applications in Google Workspace",
                    "D. to perform network traffic analysis"
                ),
                setOf("C"),
                "Cisco Cloudlock for Google Workspace provides data and application security in Google Workspace environments. It offers data loss prevention, user behavior analytics, and compliance monitoring capabilities, helping organizations protect their sensitive data and applications in Google Workspace.",
                "https://www.cisco.com/c/en/us/products/security/cloudlock/index.html",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "Which Cisco security solution provides secure access to Microsoft 365?",
                listOf(
                    "A. Cisco Cloudlock for Microsoft 365",
                    "B. Cisco ISE",
                    "C. Cisco Umbrella",
                    "D. Cisco Firepower"
                ),
                setOf("A"),
                "Cisco Cloudlock for Microsoft 365 provides secure access to Microsoft 365 by offering visibility, compliance, data security, and threat protection for Microsoft 365 services. It helps organizations secure their Microsoft 365 usage and protect sensitive data.",
                "https://www.cisco.com/c/en/us/products/security/cloudlock/index.html",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "What is the purpose of Cisco Cloudlock for Salesforce?",
                listOf(
                    "A. to provide network access control and policy enforcement",
                    "B. to manage firewall rules and policies",
                    "C. to protect data and applications in Salesforce",
                    "D. to perform network traffic analysis"
                ),
                setOf("C"),
                "Cisco Cloudlock for Salesforce provides data and application security in Salesforce environments. It offers data loss prevention, user behavior analytics, and compliance monitoring capabilities, helping organizations protect their sensitive data and applications in Salesforce.",
                "https://www.cisco.com/c/en/us/products/security/cloudlock/index.html",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "What is the purpose of Cisco Cloudlock for Box?",
                listOf(
                    "A. to provide network access control and policy enforcement",
                    "B. to manage firewall rules and policies",
                    "C. to protect data and applications in Box",
                    "D. to perform network traffic analysis"
                ),
                setOf("C"),
                "Cisco Cloudlock for Box provides data and application security in Box environments. It offers data loss prevention, user behavior analytics, and compliance monitoring capabilities, helping organizations protect their sensitive data and applications in Box.",
                "https://www.cisco.com/c/en/us/products/security/cloudlock/index.html",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "Which Cisco security solution provides secure access to Slack?",
                listOf(
                    "A. Cisco Cloudlock for Slack",
                    "B. Cisco ISE",
                    "C. Cisco Umbrella",
                    "D. Cisco Firepower"
                ),
                setOf("A"),
                "Cisco Cloudlock for Slack provides secure access to Slack by offering visibility, compliance, data security, and threat protection for Slack services. It helps organizations secure their Slack usage and protect sensitive data.",
                "https://www.cisco.com/c/en/us/products/security/cloudlock/index.html",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "What is the purpose of Cisco Cloudlock for GitHub?",
                listOf(
                    "A. to provide network access control and policy enforcement",
                    "B. to manage firewall rules and policies",
                    "C. to protect data and applications in GitHub",
                    "D. to perform network traffic analysis"
                ),
                setOf("C"),
                "Cisco Cloudlock for GitHub provides data and application security in GitHub environments. It offers data loss prevention, user behavior analytics, and compliance monitoring capabilities, helping organizations protect their sensitive data and applications in GitHub.",
                "https://www.cisco.com/c/en/us/products/security/cloudlock/index.html",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "What is the purpose of Cisco Cloudlock for Jira?",
                listOf(
                    "A. to provide network access control and policy enforcement",
                    "B. to manage firewall rules and policies",
                    "C. to protect data and applications in Jira",
                    "D. to perform network traffic analysis"
                ),
                setOf("C"),
                "Cisco Cloudlock for Jira provides data and application security in Jira environments. It offers data loss prevention, user behavior analytics, and compliance monitoring capabilities, helping organizations protect their sensitive data and applications in Jira.",
                "https://www.cisco.com/c/en/us/products/security/cloudlock/index.html",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "Which Cisco security solution provides secure access to Confluence?",
                listOf(
                    "A. Cisco Cloudlock for Confluence",
                    "B. Cisco ISE",
                    "C. Cisco Umbrella",
                    "D. Cisco Firepower"
                ),
                setOf("A"),
                "Cisco Cloudlock for Confluence provides secure access to Confluence by offering visibility, compliance, data security, and threat protection for Confluence services. It helps organizations secure their Confluence usage and protect sensitive data.",
                "https://www.cisco.com/c/en/us/products/security/cloudlock/index.html",
                QuestionCategory.SCOR_PART_1
            ),
            Question.DragAndDrop(
                question = "Drag and drop the VPN functions from the left onto the description on the right.",
                items = listOf(
                    "SHA-1",
                    "RSA",
                    "AES",
                    "ISAKMP"
                ),
                categories = listOf(
                    "ensures data confidentiality",
                    "defines IKE SAs",
                    "ensures data integrity",
                    "provides authentication"
                ),
                correctMapping = mapOf(
                    "AES" to "ensures data confidentiality",
                    "ISAKMP" to "defines IKE SAs",
                    "SHA-1" to "ensures data integrity",
                    "RSA" to "provides authentication"
                ),
                explanation = """The purpose of message integrity algorithms, such as Secure Hash Algorithm (SHA-1), ensures data has not been changed in transit. They use one way hash functions to determine if data has been changed.

SHA-1, which is also known as HMAC-SHA-1 is a strong cryptographic hashing algorithm, stronger than another popular algorithm known as Message Digest 5 (MD5). SHA-1 is used to provide data integrity (to guarantee data has not been altered in transit) and authentication (to guarantee data came from the source it was supposed to come from). SHA was produced to be used with the digital signature standard.

A VPN uses groundbreaking 256-bit AES encryption technology to secure your online connection against cyberattacks that can compromise your security. It also offers robust protocols to combat malicious attacks and reinforce your online identity.

IKE SAs describe the security parameters between two IKE devices, the first stage in establishing IPSec.""",
                reference = "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                category = QuestionCategory.SCOR_PART_1
            ),
            Question.DragAndDrop(
                question = "Drag and drop the threats from the left onto examples of that threat on the right.",
                items = listOf(
                    "DoS/DDoS",
                    "Insecure APIs",
                    "data breach",
                    "compromised credentials"
                ),
                categories = listOf(
                    "A stolen customer database that contained social security numbers and was published online",
                    "A phishing site appearing to be a legitimate login page captures user login information",
                    "An application attack using botnets from multiple remote locations that flood a web application causing a degraded performance or a complete outage",
                    "A malicious user gained access to an organization's database from a cloud-based application programming interface that lacked strong authentication controls"
                ),
                correctMapping = mapOf(
                    "data breach" to "A stolen customer database that contained social security numbers and was published online",
                    "compromised credentials" to "A phishing site appearing to be a legitimate login page captures user login information",
                    "DoS/DDoS" to "An application attack using botnets from multiple remote locations that flood a web application causing a degraded performance or a complete outage",
                    "Insecure APIs" to "A malicious user gained access to an organization's database from a cloud-based application programming interface that lacked strong authentication controls"
                ),
                explanation = """A data breach is the intentional or unintentional release of secure or private/confidential information to an untrusted environment.

When your credentials have been compromised, it means someone other than you may be in possession of your account information, such as your username and/or password.""",
                reference = "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                category = QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "Refer to the exhibit.\n\nTraffic is not passing through IPsec site-to-site VPN on the Firepower Threat Defense appliance. What is causing this issue?",
                listOf(
                    "A. No split-tunnel policy is defined on the Firepower Threat Defense appliance.",
                    "B. The access control policy is not allowing VPN traffic in.",
                    "C. Site-to-site VPN peers are using different encryption algorithms.",
                    "D. Site-to-site VPN preshared keys are mismatched."
                ),
                setOf("B"),
                "If sysopt permit-vpn is not enabled then an access control policy must be created to allow the VPN traffic through the FTD device. If sysopt permit-vpn is enabled skip creating an access control policy.",
                "https://www.cisco.com/c/en/us/support/docs/security-vpn/ipsec-negotiation-ike-protocols/215470-site-to-site-vpn-configuration-on-ftd-ma.html",
                QuestionCategory.SCOR_PART_1,
                "question_23_ipsec_output"
            ),
            Question.MultipleChoice(
                """Refer to the exhibit.

ip dhcp snooping
ip dhcp snooping vlan 41,44
!
interface GigabitEthernet1/0/1
 description Uplink_To_Distro_Switch_g1/0/11
 switchport trunk native vlan 999
 switchport trunk allowed vlan 40,41,44
 switchport mode trunk
An organization is using DHCP Snooping within their network. A user on VLAN 41 on a new switch is complaining that an IP address is not being obtained. Which command should be configured on the switch interface in order to provide the user with network connectivity?""",
                listOf(
                    "A. ip dhcp snooping verify mac-address",
                    "B. ip dhcp snooping limit 41",
                    "C. ip dhcp snooping vlan 41",
                    "D. ip dhcp snooping trust"
                ),
                setOf("D"),
                """To understand DHCP snooping we need to learn about DHCP spoofing attack first.

DHCP spoofing is a type of attack in that the attacker listens for DHCP Requests from clients and answers them with fake DHCP Response before the authorized DHCP Response comes to the clients. The fake DHCP Response often gives its IP address as the client default gateway -> all the traffic sent from the client will go through the attacker computer, the attacker becomes a "man-in-the-middle".

The attacker can have some ways to make sure its fake DHCP Response arrives first. In fact, if the attacker is "closer" than the DHCP Server then he doesn't need to do anything. Or he can DoS the DHCP Server so that it can't send the DHCP Response.

DHCP snooping can prevent DHCP spoofing attacks. DHCP snooping is a Cisco Catalyst feature that determines which switch ports can respond to DHCP requests. Ports are identified as trusted and untrusted.

Only ports that connect to an authorized DHCP server are trusted, and allowed to send all types of DHCP messages. All other ports on the switch are untrusted and can send only DHCP requests. If a DHCP response is seen on an untrusted port, the port is shut down.

The port connected to a DHCP server should be configured as trusted port with the "ip dhcp snooping trust" command. Other ports connecting to hosts are untrusted ports by default.

In this question, we need to configure the uplink to "trust" (under interface Gi1/0/1) as shown below.""",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "What is managed by Cisco Security Manager?",
                listOf(
                    "A. access point",
                    "B. Secure Web Appliance",
                    "C. ASA",
                    "D. Secure Email Gateway"
                ),
                setOf("C"),
                """Cisco Security Manager provides a comprehensive management solution for:
– Cisco ASA 5500 Series Adaptive Security Appliances
– Cisco intrusion prevention systems 4200 and 4500 Series Sensors
– Cisco AnyConnect Secure Mobility Client""",
                "https://www.cisco.com/c/en/us/products/security/security-manager/index.html",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "How does Cisco Advanced Phishing Protection protect users?",
                listOf(
                    "A. It validates the sender by using DKIM.",
                    "B. It determines which identities are perceived by the sender",
                    "C. It utilizes sensors that send messages securely.",
                    "D. It uses machine learning and real-time behavior analytics."
                ),
                setOf("D"),
                "Cisco Advanced Phishing Protection provides sender authentication and BEC detection capabilities. It uses advanced machine learning techniques, real-time behavior analytics, relationship modeling, and telemetry to protect against identity deception-based threats.",
                "https://docs.ces.cisco.com/docs/advanced-phishing-protection",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "What is a benefit of using Cisco FMC over Cisco ASDM?",
                listOf(
                    "A. Cisco FMC uses Java while Cisco ASDM uses HTML5.",
                    "B. Cisco FMC provides centralized management while Cisco ASDM does not.",
                    "C. Cisco FMC supports pushing configurations to devices while Cisco ASDM does not.",
                    "D. Cisco FMC supports all firewall products whereas Cisco ASDM only supports Cisco ASA devices"
                ),
                setOf("B"),
                """Cisco FTD devices, Cisco Firepower devices, and the Cisco ASA FirePOWER modules can be managed by the Firepower Management Center (FMC), formerly known as the FireSIGHT Management Center -> Answer D is not correct

Note: The ASA FirePOWER module runs on the separately upgraded ASA operating system

"You cannot use an FMC to manage ASA firewall functions."

The Cisco Secure Firewall Threat Defense Manager (Firepower Management Center) increases the effectiveness of your Cisco network security solutions by providing centralized, integrated, and streamlined management.""",
                "https://www.cisco.com/c/en/us/products/collateral/security/firesight-management-center/datasheet-c78-736775.html",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "What is a key difference between Cisco Firepower and Cisco ASA?",
                listOf(
                    "A. Cisco ASA provides access control while Cisco Firepower does not.",
                    "B. Cisco Firepower provides identity-based access control while Cisco ASA does not.",
                    "C. Cisco Firepower natively provides intrusion prevention capabilities while Cisco ASA does not.",
                    "D. Cisco ASA provides SSL inspection while Cisco Firepower does not."
                ),
                setOf("C"),
                "Cisco Firepower natively provides intrusion prevention capabilities, while Cisco ASA requires additional modules or configurations to achieve similar functionality.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "An organization is implementing URL blocking using Cisco Umbrella. The users are able to go to some sites but other sites are not accessible due to an error. Why is the error occurring?",
                listOf(
                    "A. Client computers do not have the Cisco Umbrella Root CA certificate installed.",
                    "B. IP-Layer Enforcement is not configured.",
                    "C. Client computers do not have an SSL certificate deployed from an internal CA server.",
                    "D. Intelligent proxy and SSL decryption is disabled in the policy."
                ),
                setOf("A"),
                """Other features are dependent on SSL Decryption functionality, which requires the Cisco Umbrella root certificate. Having the SSL Decryption feature improves:
Custom URL Blocking—Required to block the HTTPS version of a URL.

Umbrella's Block Page and Block Page Bypass features present an SSL certificate to browsers that make connections to HTTPS sites. This SSL certificate matches the requested site but will be signed by the Cisco Umbrella certificate authority (CA). If the CA is not trusted by your browser, an error page may be displayed. Typical errors include "The security certificate presented by this website was not issued by a trusted certificate authority" (Internet Explorer), "The site's security certificate is not trusted!" (Google Chrome) or "This Connection is Untrusted" (Mozilla Firefox). Although the error page is expected, the message displayed can be confusing and you may wish to prevent it from appearing.

To avoid these error pages, install the Cisco Umbrella root certificate into your browser or the browsers of your users—if you're a network admin.""",
                "https://docs.umbrella.com/deployment-umbrella/docs/rebrand-cisco-certificate-import-information",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "Which two aspects of the cloud PaaS model are managed by the customer but not the provider? (Choose two)",
                listOf(
                    "A. virtualization",
                    "B. middleware",
                    "C. operating systems",
                    "D. applications",
                    "E. data"
                ),
                setOf("D", "E"),
                "In the Platform as a Service (PaaS) model, customers are responsible for managing their applications and data, while the provider manages the underlying infrastructure, operating systems, and middleware.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "What is an attribute of the DevSecOps process?",
                listOf(
                    "A. mandated security controls and check lists",
                    "B. security scanning and theoretical vulnerabilities",
                    "C. development security",
                    "D. isolated security team"
                ),
                setOf("C"),
                """DevSecOps (development, security, and operations) is a concept used in recent years to describe how to move security activities to the start of the development life cycle and have built-in security practices in the continuous integration/continuous deployment (CI/CD) pipeline. Thus minimizing vulnerabilities and bringing security closer to IT and business objectives.

Three key things make a real DevSecOps environment:
+ Security testing is done by the development team.
+ Issues found during that testing is managed by the development team.
+ Fixing those issues stays within the development team.""",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "An engineer notices traffic interruption on the network. Upon further investigation, it is learned that broadcast packets have been flooding the network. What must be configured, based on a predefined threshold, to address this issue?",
                listOf(
                    "A. Bridge Protocol Data Unit guard",
                    "B. embedded event monitoring",
                    "C. storm control",
                    "D. access control lists"
                ),
                setOf("C"),
                """Storm control prevents traffic on a LAN from being disrupted by a broadcast, multicast, or unicast storm on one of the physical interfaces. A LAN storm occurs when packets flood the LAN, creating excessive traffic and degrading network performance. Errors in the protocol-stack implementation, mistakes in network configurations, or users issuing a denial-of-service attack can cause a storm.

By using the "storm-control broadcast level [falling-threshold]" we can limit the broadcast traffic on the switch.""",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "Which two cryptographic algorithms are used with IPsec? (Choose two)",
                listOf(
                    "A. AES-BAC",
                    "B. AES-ABC",
                    "C. HMAC-SHA1/SHA2",
                    "D. Triple AMC-CBC",
                    "E. AES-CBC"
                ),
                setOf("C", "E"),
                """Cryptographic algorithms defined for use with IPsec include:
+ HMAC-SHA1/SHA2 for integrity protection and authenticity.
+ TripleDES-CBC for confidentiality
+ AES-CBC and AES-CTR for confidentiality.
+ AES-GCM and ChaCha20-Poly1305 providing confidentiality and authentication together efficiently.""",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "In which type of attack does the attacker insert their machine between two hosts that are communicating with each other?",
                listOf(
                    "A. LDAP injection",
                    "B. man-in-the-middle",
                    "C. cross-site scripting",
                    "D. insecure API"
                ),
                setOf("B"),
                "A man-in-the-middle (MITM) attack is a type of cyberattack where the attacker secretly intercepts and relays messages between two parties who believe they are communicating directly with each other. The attacker can read, modify, or inject new messages into the communication stream.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "Which Dos attack uses fragmented packets to crash a target machine?",
                listOf(
                    "A. smurf",
                    "B. MITM",
                    "C. teardrop",
                    "D. LAND"
                ),
                setOf("C"),
                "A teardrop attack is a denial-of-service (DoS) attack in which an attacker sends fragmented packets to a target machine. Since the machine receiving such packets cannot reassemble them due to a bug in TCP/IP fragmentation reassembly, the packets overlap one another, crashing the target network device. This generally happens on older operating systems such as Windows 3.1x, Windows 95, Windows NT and versions of the Linux kernel prior to 2.1.63.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                category = QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "Why is it important to have logical security controls on endpoints even though the users are trained to spot security threats and the network devices already help prevent them?",
                listOf(
                    "A. to prevent theft of the endpoints",
                    "B. because defense-in-depth stops at the network",
                    "C. to expose the endpoint to more threats",
                    "D. because human error or insider threats will still exist"
                ),
                setOf("D"),
                "Even with well-trained users and robust network security, logical security controls on endpoints remain crucial because human error and insider threats are still significant risks. These controls provide an additional layer of defense against mistakes or malicious actions.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                category = QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "Which type of API is being used when a security application notifies a controller within a software-defined network architecture about a specific security threat? (Choose two)",
                listOf(
                    "A. westbound AP",
                    "B. southbound API",
                    "C. northbound API",
                    "D. eastbound API"
                ),
                setOf("B", "C"),
                "In a software-defined network architecture, both southbound and northbound APIs play crucial roles in security threat communication. The southbound API enables communication between the controller and the network infrastructure, while the northbound API facilitates communication between the controller and the applications.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                category = QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "When planning a VPN deployment, for which reason does an engineer opt for an active/active FlexVPN configuration as opposed to DMVPN?",
                listOf(
                    "A. Multiple routers or VRFs are required.",
                    "B. Traffic is distributed statically by default.",
                    "C. Floating static routes are required.",
                    "D. HSRP is used for fallover."
                ),
                setOf("B"),
                "An active/active FlexVPN configuration is chosen when traffic needs to be distributed statically by default, as opposed to DMVPN which uses dynamic routing.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                category = QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "Which algorithm provides asymmetric encryption?",
                listOf(
                    "A. RC4",
                    "B. AES",
                    "C. RSA",
                    "D. 3DES"
                ),
                setOf("C"),
                "RSA (Rivest-Shamir-Adleman) is an asymmetric encryption algorithm that uses a pair of public and private keys for encryption and decryption.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                category = QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "What are two functions of secret key cryptography? (Choose two)",
                listOf(
                    "A. key selection without integer factorization",
                    "B. utilization of different keys for encryption and decryption",
                    "C. utilization of large prime number iterations",
                    "D. provides the capability to only know the key on one side",
                    "E. utilization of less memory"
                ),
                setOf("A", "E"),
                "Secret key cryptography is often called symmetric cryptography since the same key is used to encrypt and decrypt data. It uses less memory than public-key cryptography and doesn't require integer factorization for key selection.",
                "https://www.jigsawacademy.com/blogs/cyber-security/secret-key-cryptography/",
                category = QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "For Cisco IOS PKI, which two types of Servers are used as a distribution point for CRLs? (Choose two)",
                listOf(
                    "A. SDP",
                    "B. LDAP",
                    "C. subordinate CA",
                    "D. SCP",
                    "E. HTTP"
                ),
                setOf("B", "E"),
                "Cisco IOS PKI uses Lightweight Directory Access Protocol (LDAP) and HTTP as distribution mechanisms for certificate revocation lists (CRLs).",
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_conn_pki/configuration/15-mt/sec-pki-15-mt-book/sec-pki-overview.html",
                category = QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "Which attack type attempts to shut down a machine or network so that users are not able to access it?",
                listOf(
                    "A. smurf",
                    "B. bluesnarfing",
                    "C. MAC spoofing",
                    "D. IP spoofing"
                ),
                setOf("A"),
                "The Smurf attack is a DDoS attack in which large numbers of Internet Control Message Protocol (ICMP) packets with the intended victim's spoofed source IP are broadcast to a computer network using an IP broadcast address.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                category = QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "What is a difference between DMVPN and sVTI?",
                listOf(
                    "A. DMVPN supports tunnel encryption, whereas sVTI does not.",
                    "B. DMVPN supports dynamic tunnel establishment, whereas sVTI does not.",
                    "C. DMVPN supports static tunnel establishment, whereas sVTI does not.",
                    "D. DMVPN provides interoperability with other vendors, whereas sVTI does not."
                ),
                setOf("B"),
                "DMVPN supports dynamic tunnel establishment, while sVTI (Static Virtual Tunnel Interface) only supports static tunnel establishment.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                category = QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "What features does Cisco FTDv provide over ASAv?",
                listOf(
                    "A. Cisco FTDv runs on VMWare while ASAv does not",
                    "B. Cisco FTDv provides 1GB of firewall throughput while Cisco ASAv does not",
                    "C. Cisco FTDv runs on AWS while ASAv does not",
                    "D. Cisco FTDv supports URL filtering while ASAv does not"
                ),
                setOf("D"),
                "Cisco FTDv (Firepower Threat Defense Virtual) provides URL filtering capabilities that are not available in ASAv (Adaptive Security Appliance Virtual).",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                category = QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "In which situation should an Endpoint Detection and Response solution be chosen versus an Endpoint Protection Platform?",
                listOf(
                    "A. when there is a need for traditional anti-malware detection",
                    "B. when there is no need to have the solution centrally managed",
                    "C. when there is no firewall on the network",
                    "D. when there is a need to have more advanced detection capabilities"
                ),
                setOf("D"),
                "Endpoint Detection and Response (EDR) solutions should be chosen when there is a need for more advanced detection capabilities beyond traditional endpoint protection. EDR provides deeper visibility and response capabilities compared to basic endpoint protection platforms.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                category = QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "Which type of API is being used when a controller within a software-defined network architecture dynamically makes configuration changes on switches within the network?",
                listOf(
                    "A. westbound AP",
                    "B. southbound API",
                    "C. northbound API",
                    "D. eastbound API"
                ),
                setOf("B"),
                "Southbound APIs enable SDN controllers to dynamically make changes based on real-time demands and scalability needs.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                category = QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "An organization has two systems in their DMZ that have an unencrypted link between them for communication. The organization does not have a defined password policy and uses several default accounts on the systems. The application used on those systems also have not gone through stringent code reviews. Which vulnerability would help an attacker brute force their way into the systems?",
                listOf(
                    "A. weak passwords",
                    "B. lack of input validation",
                    "C. missing encryption",
                    "D. lack of file permission"
                ),
                setOf("A"),
                "Weak passwords and default accounts make the systems vulnerable to brute force attacks, as they can be easily guessed or cracked.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                category = QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "What is the purpose of a Netflow version 9 template record?",
                listOf(
                    "A. It specifies the data format of NetFlow processes.",
                    "B. It provides a standardized set of information about an IP flow.",
                    "C. It defines the format of data records.",
                    "D. It serves as a unique identification number to distinguish individual data records"
                ),
                setOf("C"),
                "The version 9 export format uses templates to provide access to observations of IP packet flows in a flexible and extensible manner. A template defines a collection of fields, with corresponding descriptions of structure and semantics.",
                "https://tools.ietf.org/html/rfc3954",
                category = QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "What is provided by the Secure Hash Algorithm in a VPN?",
                listOf(
                    "A. integrity",
                    "B. key exchange",
                    "C. encryption",
                    "D. authentication"
                ),
                setOf("A"),
                "The HMAC-SHA-1-96 (also known as HMAC-SHA-1) encryption technique is used by IPSec to ensure that a message has not been altered. (-> Therefore answer \"integrity\" is the best choice). HMAC-SHA-1 uses the SHA-1 specified in FIPS-190-1, combined with HMAC (as per RFC 2104), and is described in RFC 2404.",
                "https://www.ciscopress.com/articles/article.asp?p=24833&seqNum=4",
                category = QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "A network engineer is deciding whether to use stateful or stateless failover when configuring two ASAs for high availability. What is the connection status in both cases?",
                listOf(
                    "A. need to be reestablished with stateful failover and preserved with stateless failover",
                    "B. preserved with stateful failover and need to be reestablished with stateless failover",
                    "C. preserved with both stateful and stateless failover",
                    "D. need to be reestablished with both stateful and stateless failover"
                ),
                setOf("B"),
                "With stateful failover, the connection state is preserved during failover, while with stateless failover, connections need to be reestablished.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                category = QuestionCategory.SCOR_PART_1
            ),
            Question.MultipleChoice(
                "Which type of protection encrypts RSA keys when they are exported and imported?",
                listOf(
                    "A. file",
                    "B. passphrase",
                    "C. NGE",
                    "D. nonexportable"
                ),
                setOf("B"),
                "Passphrase protection encrypts RSA keys when they are exported and imported, providing an additional layer of security for key management.",
                "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide",
                category = QuestionCategory.SCOR_PART_1
            )
        ))

        // Initialize empty lists for other parts
        questionSets[QuestionCategory.SCOR_PART_2] = mutableListOf()
        questionSets[QuestionCategory.SCOR_PART_3] = mutableListOf()
        questionSets[QuestionCategory.SCOR_PART_4] = mutableListOf()
        questionSets[QuestionCategory.SCOR_PART_5] = mutableListOf()
        questionSets[QuestionCategory.SCOR_PART_6] = mutableListOf()
        questionSets[QuestionCategory.SCOR_PART_7] = mutableListOf()
    }

    // Get a batch of questions for a specific part
    fun getQuestionsBatch(category: QuestionCategory, startIndex: Int = 0, count: Int = BATCH_SIZE): List<Question> {
        val questions = questionSets[category] ?: emptyList()
        val endIndex = minOf(startIndex + count, questions.size)
        return questions.subList(startIndex, endIndex)
    }

    // Get total number of questions for a specific part
    fun getTotalQuestions(category: QuestionCategory): Int = questionSets[category]?.size ?: 0

    // Get a random batch of questions for a specific part
    fun getRandomQuestions(category: QuestionCategory, count: Int = BATCH_SIZE): List<Question> {
        Log.d("QuizQuestions", "getRandomQuestions called for category: ${category.name} with count: $count")
        val questions = questionSets[category] ?: emptyList()
        Log.d("QuizQuestions", "Total questions available for ${category.name}: ${questions.size}")
        val result = if (count >= questions.size) {
            questions.shuffled()
        } else {
            questions.shuffled().take(count)
        }
        Log.d("QuizQuestions", "Returning ${result.size} questions")
        return result
    }

    // Get questions by category
    fun getQuestionsByCategory(category: String): List<Question> {
        val questionCategory = try {
            QuestionCategory.valueOf(category)
        } catch (e: IllegalArgumentException) {
            return emptyList()
        }
        return questionSets[questionCategory] ?: emptyList()
    }

    // Add a new question to a specific part
    fun addQuestion(category: QuestionCategory, question: Question) {
        questionSets.getOrPut(category) { mutableListOf() }.add(question)
    }

    // Add multiple questions to a specific part
    fun addQuestions(category: QuestionCategory, questions: List<Question>) {
        questionSets.getOrPut(category) { mutableListOf() }.addAll(questions)
    }

    // Clear all questions for a specific part
    fun clearQuestions(category: QuestionCategory) {
        questionSets[category]?.clear()
    }

    // Clear all questions for all parts
    fun clearAllQuestions() {
        questionSets.values.forEach { it.clear() }
    }
} 