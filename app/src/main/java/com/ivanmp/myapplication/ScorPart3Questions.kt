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
            )
        )
    }
}
