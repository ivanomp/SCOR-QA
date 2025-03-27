package com.ivanmp.myapplication

import android.util.Log

object QuizQuestions {
    private val allQuestions = mutableListOf<Question>()
    private var currentBatchStart = 0
    private const val BATCH_SIZE = 100

    // Initialize questions
    init {
        allQuestions.addAll(listOf(
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
                category = QuestionCategory.SECURITY_TECHNOLOGIES
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
                QuestionCategory.SECURITY_TECHNOLOGIES
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
                QuestionCategory.NETWORK_SECURITY_FUNDAMENTALS
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
                QuestionCategory.SECURITY_TECHNOLOGIES
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
                QuestionCategory.SECURITY_TECHNOLOGIES
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
                QuestionCategory.NETWORK_SECURITY_FUNDAMENTALS
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
                QuestionCategory.SECURITY_TECHNOLOGIES
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
                QuestionCategory.SECURITY_TECHNOLOGIES
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
                QuestionCategory.SECURITY_TECHNOLOGIES
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
                QuestionCategory.SECURITY_TECHNOLOGIES
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
                QuestionCategory.NETWORK_SECURITY_FUNDAMENTALS
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
                QuestionCategory.SECURITY_TECHNOLOGIES
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
                QuestionCategory.SECURITY_TECHNOLOGIES
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
                QuestionCategory.SECURITY_MANAGEMENT
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
                QuestionCategory.SECURITY_TECHNOLOGIES
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
                QuestionCategory.NETWORK_SECURITY_FUNDAMENTALS
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
                QuestionCategory.SECURITY_TECHNOLOGIES,
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
                QuestionCategory.SECURITY_TECHNOLOGIES
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
                QuestionCategory.SECURITY_TECHNOLOGIES
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
                """The Cisco Web Security Appliance (WSA) includes a web proxy, a threat analytics engine, antimalware engine, policy management, and reporting in a single physical or virtual appliance. The main use of the Cisco WSA is to protect users from accessing malicious websites and being infected by malware.

When requests are being redirected to the WSA transparently, the WSA must pretend to be the OCS (origin content server), since the client is unaware of the existence of a proxy. On the contrary, if a request is explicitly sent to the WSA, the WSA will respond with it's own IP information.

In transparent mode, network infrastructure devices redirect web traffic to the proxy using policy-based routing (PBR) or Web Cache Communication Protocol (WCCP) on Cisco ASA, routers, or switches.""",
                "https://www.cisco.com/c/en/us/tech/content-networking/web-cache-communications-protocol-wccp/index.html",
                QuestionCategory.SECURITY_TECHNOLOGIES
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
                """URL conditions in access control rules allow you to limit the websites that users on your network can access. This feature is called URL filtering. There are two ways you can use access control to specify URLs you want to block:
- With any license, you can manually specify individual URLs, groups of URLs, and URL lists and feeds to achieve granular, custom control over web traffic.
- With a URL Filtering license, you can also control access to websites based on the URL's general classification, or category, and risk level, or reputation.

Using category and reputation data simplifies policy creation and administration and ensures that the system uses up-to-date information to filter requested URLs. Malicious sites that represent security threats such as malware, spam, botnets, and phishing may appear and disappear faster than you can update and deploy new policies.""",
                "https://www.cisco.com/c/en/us/td/docs/security/firepower/60/configuration/guide/fpmc-config-guide-v60/Access_Control_Rules__URL_Filtering.html",
                QuestionCategory.SECURITY_TECHNOLOGIES
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
                QuestionCategory.SECURITY_TECHNOLOGIES
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
                """If sysopt permit-vpn is not enabled then an access control policy must be created to allow the VPN traffic through the FTD device. If sysopt permit-vpn is enabled skip creating an access control policy.

Looking at the exhibit, we can see:
- The crypto map and access lists are properly configured
- The IPsec parameters like encryption (B6F5EA53) and SPI (84348DEE) are established
- There are no decryption/encryption failures (#pkts decrypt/encrypt failures: 0)
- The peers are successfully communicating (current_peer shows the remote IP)

This indicates the VPN tunnel itself is working correctly, but traffic is being blocked by access control policies.""",
                "https://www.cisco.com/c/en/us/support/docs/security-vpn/ipsec-negotiation-ike-protocols/215470-site-to-site-vpn-configuration-on-ftd-ma.html",
                QuestionCategory.SECURITY_TECHNOLOGIES,
                "q23_ipsec_vpn_output"
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
        Log.d("QuizQuestions", "getRandomQuestions called with count: $count")
        Log.d("QuizQuestions", "Total questions available: ${allQuestions.size}")
        val result = if (count >= allQuestions.size) {
            allQuestions.shuffled()
        } else {
            allQuestions.shuffled().take(count)
        }
        Log.d("QuizQuestions", "Returning ${result.size} questions")
        return result
    }

    // Get questions by category (if you want to add categories later)
    fun getQuestionsByCategory(category: String): List<Question> {
        return allQuestions.filter { question ->
            when (question) {
                is Question.MultipleChoice -> question.category.name == category
                is Question.DragAndDrop -> question.category.name == category
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