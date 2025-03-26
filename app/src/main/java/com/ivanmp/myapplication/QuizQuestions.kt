package com.ivanmp.myapplication

object QuizQuestions {
    val questions = listOf(
        Question.MultipleChoice(
            "What is a characteristic of a bridge group in ASA Firewall transparent mode?",
            listOf(
                "A. It includes multiple interfaces and access rules between interfaces are customizable",
                "B. It is a Layer 3 segment and includes one port and customizable access rules",
                "C. It allows ARP traffic with a single access rule",
                "D. It has an IP address on its BVI interface and is used for management traffic"
            ),
            listOf("A"),
            "A bridge group is a set of interfaces that the ASA bridges rather than routes. It includes a BVI for traffic source identification and supports multiple interfaces. Management traffic is handled separately.",
            "https://www.cisco.com/c/en/us/td/docs/security/asa/asa95/configuration/general/asa-95-general-config/intro-fw.html"
        ),
        Question.DragAndDrop(
            "Drag and drop the capabilities of Cisco Firepower versus Cisco AMP from the left into the appropriate category on the right.",
            listOf(
                "provides the ability to perform network discovery",
                "provides detection, blocking, tracking, analyse and remediation to protect against targeted persistent malware attacks",
                "provides intrusion prevention before malware comprises the host",
                "provides superior threat prevention and mitigation for known and unknown threats",
                "provides the root cause of a threat based on the indicators of compromise seen",
                "provides outbreak control through custom detections"
            ),
            listOf("Cisco Firepower", "Cisco AMP"),
            mapOf(
                "provides the ability to perform network discovery" to "Cisco Firepower",
                "provides detection, blocking, tracking, analyse and remediation to protect against targeted persistent malware attacks" to "Cisco AMP",
                "provides intrusion prevention before malware comprises the host" to "Cisco Firepower",
                "provides superior threat prevention and mitigation for known and unknown threats" to "Cisco Firepower",
                "provides the root cause of a threat based on the indicators of compromise seen" to "Cisco AMP",
                "provides outbreak control through custom detections" to "Cisco AMP"
            ),
            """The Firepower System uses network discovery and identity policies to collect host, application, and user data for traffic on your network. You can use certain types of discovery and identity data to build a comprehensive map of your network assets, perform forensic analysis, behavioral profiling, access control, and mitigate and respond to the vulnerabilities and exploits to which your organization is susceptible.

The Cisco Advanced Malware Protection (AMP) solution enables you to detect and block malware, continuously analyze for malware, and get retrospective alerts. AMP for Networks delivers network-based advanced malware protection that goes beyond point-in-time detection to protect your organization across the entire attack continuum – before, during, and after an attack. Designed for Cisco Firepower network threat appliances, AMP for Networks detects, blocks, tracks, and contains malware threats across multiple threat vectors within a single system. It also provides the visibility and control necessary to protect your organization against highly sophisticated, targeted, zero‑day, and persistent advanced malware threats.""",
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
            listOf("B"),
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
            listOf("A", "D"),
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
            listOf("D"),
            "APIs enable network management and monitoring programmatically outside the default DNAC GUI environment.",
            "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
        ),
        // Add more questions here in the same format:
        /*
        Question(
            "Your question text here",
            listOf(
                "A. First option",
                "B. Second option",
                "C. Third option",
                "D. Fourth option"
            ),
            listOf("A"), // For multiple correct answers use: listOf("A", "C")
            "Your explanation here",
            "Reference source or URL"
        ),
        */
    )
} 