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
            id = 38,
            text = "What is the purpose of the My Devices Portal in a Cisco ISE environment?",
            options = listOf(
                "to register new laptops and mobile devices",
                "to request a newly provisioned mobile device",
                "to provision userless and agentless systems",
                "to manage and deploy antivirus definitions and patches on systems owned by the end user"
            ),
            correctAnswer = "to register new laptops and mobile devices",
            explanation = "Depending on your company policy, you might be able to use your mobile phones, tablets, printers, Internet radios, and other network devices on your company's network. You can use the My Devices portal to register and manage these devices on your company's network.",
            reference = "https://www.cisco.com/c/en/us/td/docs/security/ise/2-4/mydevices/b_mydevices_2x.html"
        ),
        Question.MultipleChoice(
            id = 39,
            text = "An organization is using DHCP Snooping within their network. A user on VLAN 41 on a new switch is complaining that an IP address is not being obtained. Which command should be configured on the switch interface in order to provide the user with network connectivity?",
            options = listOf(
                "ip dhcp snooping verify mac-address",
                "ip dhcp snooping limit 41",
                "ip dhcp snooping vlan 41",
                "ip dhcp snooping trust"
            ),
            correctAnswer = "ip dhcp snooping trust",
            explanation = "The port connected to a DHCP server should be configured as trusted port with the \"ip dhcp snooping trust\" command. Other ports connecting to hosts are untrusted ports by default."
        ),
        Question.MultipleChoice(
            id = 40,
            text = "What is the purpose of the certificate signing request when adding a new certificate for a server?",
            options = listOf(
                "It is the password for the certificate that is needed to install it with.",
                "It provides the server information so a certificate can be created and signed",
                "It provides the certificate client information so the server can authenticate against it when installing",
                "It is the certificate that will be loaded onto the server"
            ),
            correctAnswer = "It provides the server information so a certificate can be created and signed",
            explanation = "A certificate signing request (CSR) is one of the first steps towards getting your own SSL Certificate. Generated on the same server you plan to install the certificate on, the CSR contains information (e.g. common name, organization, country) that the Certificate Authority (CA) will use to create your certificate. It also contains the public key that will be included in your certificate and is signed with the corresponding private key."
        )
    )
}

data class DragItem(
    val text: String,
    var currentCategory: String? = null
) 