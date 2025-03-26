package com.ivanmp.myapplication

object QuizQuestions {
    val questions = listOf(
        Question(
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
        Question(
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
        Question(
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
            ""
        ),
        Question(
            "What provides the ability to program and monitor networks from somewhere other than the DNAC GUI?",
            listOf(
                "A. NetFlow",
                "B. Desktop client",
                "C. ASDM",
                "D. API"
            ),
            listOf("D"),
            "APIs enable network management and monitoring programmatically outside the default DNAC GUI environment.",
            ""
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