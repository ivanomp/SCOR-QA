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
        return allQuestions
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