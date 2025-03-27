package com.ivanmp.myapplication

sealed class Question {
    data class MultipleChoice(
        val id: Int,
        val text: String,
        val options: List<String>,
        val correctAnswer: String,
        val explanation: String,
        val reference: String? = null,
        val imageResourceName: String? = null
    ) : Question()

    data class DragAndDrop(
        val id: Int,
        val text: String,
        val items: List<String>,
        val categories: List<String>,
        val correctMapping: Map<String, String>, // item to category mapping
        val explanation: String,
        val reference: String,
        val imageResourceName: String? = null
    ) : Question()
}

object QuestionBank {
    val questions = listOf(
        Question.MultipleChoice(
            id = 1,
            text = "What is a characteristic of a bridge group in ASA Firewall transparent mode?",
            options = listOf(
                "A. It allows the ASA to act as a Layer 2 device",
                "B. It requires IP addresses on the bridge group interfaces",
                "C. It supports dynamic routing protocols",
                "D. It can only be used with VLANs"
            ),
            correctAnswer = "A. It allows the ASA to act as a Layer 2 device",
            explanation = "A bridge group in transparent mode allows the ASA to act as a Layer 2 device, forwarding traffic based on MAC addresses rather than IP addresses.",
            reference = "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
        ),
        Question.DragAndDrop(
            id = 2,
            text = "Categorize the following capabilities into either Cisco Firepower or Cisco AMP:",
            items = listOf(
                "Network-based malware protection",
                "File reputation and sandboxing",
                "Endpoint visibility and control",
                "Application visibility and control",
                "Network access control",
                "Threat intelligence integration"
            ),
            categories = listOf("Cisco Firepower", "Cisco AMP"),
            correctMapping = mapOf(
                "Network-based malware protection" to "Cisco Firepower",
                "File reputation and sandboxing" to "Cisco AMP",
                "Endpoint visibility and control" to "Cisco AMP",
                "Application visibility and control" to "Cisco Firepower",
                "Network access control" to "Cisco Firepower",
                "Threat intelligence integration" to "Cisco Firepower"
            ),
            explanation = "Cisco Firepower provides network-focused security features like network-based malware protection, application control, and network access control. Cisco AMP focuses on endpoint security with features like file reputation, sandboxing, and endpoint visibility.",
            reference = "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
        ),
        Question.MultipleChoice(
            id = 3,
            text = "When Cisco and other industry organizations publish and inform users of known security findings and vulnerabilities, which name is used?",
            options = listOf(
                "A. Common Security Exploits",
                "B. Common Vulnerabilities and Exposures",
                "C. Common Exploits and Vulnerabilities",
                "D. Common Vulnerabilities, Exploits and Threats"
            ),
            correctAnswer = "B. Common Vulnerabilities and Exposures",
            explanation = "The industry standard identifier for public vulnerability disclosure is the Common Vulnerabilities and Exposures (CVE), sponsored by US-CERT.",
            reference = "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
        ),
        Question.MultipleChoice(
            id = 4,
            text = "Which two fields are defined in the NetFlow flow? (Choose two)",
            options = listOf(
                "A. type of service byte",
                "B. class of service bits",
                "C. Layer 4 protocol type",
                "D. destination port",
                "E. output logical interface"
            ),
            correctAnswer = "A. type of service byte",
            explanation = "NetFlow v5 defines a flow with seven key fields including the type of service byte and the destination port, among others.",
            reference = "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
        ),
        Question.MultipleChoice(
            id = 5,
            text = "What provides the ability to program and monitor networks from somewhere other than the DNAC GUI?",
            options = listOf(
                "A. NetFlow",
                "B. Desktop client",
                "C. ASDM",
                "D. API"
            ),
            correctAnswer = "D. API",
            explanation = "APIs enable network management and monitoring programmatically outside the default DNAC GUI environment.",
            reference = "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
        ),
        Question.MultipleChoice(
            id = 6,
            text = "Which Cisco security solution provides network visibility and threat detection through deep packet inspection?",
            options = listOf(
                "A. Cisco ISE",
                "B. Cisco Stealthwatch",
                "C. Cisco Umbrella",
                "D. Cisco ESA"
            ),
            correctAnswer = "B. Cisco Stealthwatch",
            explanation = "Cisco Stealthwatch provides network visibility and threat detection through deep packet inspection and NetFlow analysis.",
            reference = "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
        ),
        Question.MultipleChoice(
            id = 7,
            text = "What is the primary function of Cisco ISE?",
            options = listOf(
                "A. Network monitoring",
                "B. Access control and policy enforcement",
                "C. Email security",
                "D. Web security"
            ),
            correctAnswer = "B. Access control and policy enforcement",
            explanation = "Cisco ISE (Identity Services Engine) is primarily used for network access control, policy enforcement, and identity management.",
            reference = "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
        ),
        Question.MultipleChoice(
            id = 8,
            text = "Which security feature is NOT typically associated with Cisco Umbrella?",
            options = listOf(
                "A. DNS security",
                "B. Cloud-delivered firewall",
                "C. Network access control",
                "D. Threat intelligence"
            ),
            correctAnswer = "C. Network access control",
            explanation = "Cisco Umbrella provides DNS security, cloud-delivered firewall, and threat intelligence, but not network access control (which is handled by ISE).",
            reference = "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
        ),
        Question.MultipleChoice(
            id = 9,
            text = "What is the main purpose of Cisco ESA (Email Security Appliance)?",
            options = listOf(
                "A. Network monitoring",
                "B. Email security and spam filtering",
                "C. Web security",
                "D. Access control"
            ),
            correctAnswer = "B. Email security and spam filtering",
            explanation = "Cisco ESA is specifically designed for email security, including spam filtering, malware protection, and email encryption.",
            reference = "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
        ),
        Question.MultipleChoice(
            id = 10,
            text = "Which Cisco security solution provides cloud-based web security and data protection?",
            options = listOf(
                "A. Cisco WSA",
                "B. Cisco Cloudlock",
                "C. Cisco ESA",
                "D. Cisco ISE"
            ),
            correctAnswer = "B. Cisco Cloudlock",
            explanation = "Cisco Cloudlock provides cloud-based web security and data protection for cloud applications and services.",
            reference = "CCNP And CCIE Security Core SCOR 350-701 Official Cert Guide"
        )
    )
}

data class DragItem(
    val text: String,
    var currentCategory: String? = null
) 