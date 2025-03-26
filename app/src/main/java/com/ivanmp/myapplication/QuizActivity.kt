package com.ivanmp.myapplication

import android.animation.ObjectAnimator
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.view.animation.AccelerateDecelerateInterpolator
import android.view.animation.AnimationUtils
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.progressindicator.LinearProgressIndicator

class QuizActivity : AppCompatActivity() {
    private lateinit var progressIndicator: LinearProgressIndicator
    private lateinit var questionNumberText: TextView
    private lateinit var questionText: TextView
    private lateinit var optionsContainer: LinearLayout
    private lateinit var submitButton: MaterialButton
    private lateinit var explanationCard: MaterialCardView
    private lateinit var resultText: TextView
    private lateinit var explanationText: TextView
    private lateinit var nextButton: MaterialButton

    private var currentQuestionIndex = 0
    private var score = 0
    private var questions = listOf<Question>()
    private var currentQuestion: Question? = null
    private val selectedOptions = mutableSetOf<String>()
    private lateinit var soundManager: SoundManager

    override fun onCreate(savedInstanceState: Bundle?) {
        try {
            super.onCreate(savedInstanceState)
            setContentView(R.layout.activity_quiz)

            // Initialize managers
            soundManager = SoundManager(this)

            // Initialize views
            initializeViews()

            // Load questions
            questions = loadQuestions()
            
            // Start quiz
            showQuestion()
        } catch (e: Exception) {
            Log.e("QuizActivity", "Error in onCreate", e)
            showErrorDialog()
        }
    }

    private fun initializeViews() {
        try {
            progressIndicator = findViewById(R.id.progressIndicator)
            questionNumberText = findViewById(R.id.questionNumberText)
            questionText = findViewById(R.id.questionText)
            optionsContainer = findViewById(R.id.optionsContainer)
            submitButton = findViewById(R.id.submitButton)
            explanationCard = findViewById(R.id.explanationCard)
            resultText = findViewById(R.id.resultText)
            explanationText = findViewById(R.id.explanationText)
            nextButton = findViewById(R.id.nextButton)
        } catch (e: Exception) {
            Log.e("QuizActivity", "Error initializing views", e)
            throw e
        }
    }

    private fun showQuestion() {
        try {
            if (currentQuestionIndex < questions.size) {
                currentQuestion = questions[currentQuestionIndex]
                selectedOptions.clear()
                
                // Update question text with multiple answer indicator if needed
                val questionPrefix = if (currentQuestion?.correct?.size ?: 0 > 1) {
                    "(Choose ${currentQuestion?.correct?.size})"
                } else ""
                questionText.text = "$questionPrefix ${currentQuestion?.question}"
                
                optionsContainer.removeAllViews()
                explanationCard.visibility = View.GONE
                nextButton.visibility = View.GONE
                submitButton.visibility = View.GONE

                // Update question number
                questionNumberText.text = getString(R.string.question_number, currentQuestionIndex + 1, questions.size)

                // Animate question text
                val slideIn = AnimationUtils.loadAnimation(this, android.R.anim.slide_in_left)
                slideIn.duration = 500
                questionText.startAnimation(slideIn)

                currentQuestion?.options?.forEach { option ->
                    val button = MaterialButton(this).apply {
                        text = option
                        textSize = 16f
                        textAlignment = View.TEXT_ALIGNMENT_VIEW_START
                        backgroundTintList = ContextCompat.getColorStateList(context, android.R.color.white)
                        setTextColor(ContextCompat.getColor(context, android.R.color.darker_gray))
                        elevation = 4f
                        strokeColor = ContextCompat.getColorStateList(context, android.R.color.darker_gray)
                        strokeWidth = 1
                        cornerRadius = resources.getDimensionPixelSize(android.R.dimen.notification_large_icon_height) / 8

                        layoutParams = LinearLayout.LayoutParams(
                            LinearLayout.LayoutParams.MATCH_PARENT,
                            LinearLayout.LayoutParams.WRAP_CONTENT
                        ).apply {
                            setMargins(0, 8, 0, 8)
                        }
                        setPadding(32, 24, 32, 24)
                        setOnClickListener { onOptionSelected(this, option) }
                    }
                    optionsContainer.addView(button)
                    
                    // Animate each option button
                    val fadeIn = AnimationUtils.loadAnimation(this, android.R.anim.fade_in)
                    fadeIn.duration = 500
                    button.startAnimation(fadeIn)
                }

                // Update progress
                updateProgress()
            } else {
                showQuizComplete()
            }
        } catch (e: Exception) {
            Log.e("QuizActivity", "Error showing question", e)
            showErrorDialog()
        }
    }

    private fun onOptionSelected(button: MaterialButton, option: String) {
        try {
            val letter = option.substringBefore(".")
            
            if (selectedOptions.contains(letter)) {
                // Deselect option
                selectedOptions.remove(letter)
                button.backgroundTintList = ContextCompat.getColorStateList(this, android.R.color.white)
                button.setTextColor(ContextCompat.getColor(this, android.R.color.darker_gray))
            } else {
                // Select option
                if (currentQuestion?.correct?.size == 1) {
                    // Single answer question - clear previous selection
                    selectedOptions.clear()
                    for (i in 0 until optionsContainer.childCount) {
                        val btn = optionsContainer.getChildAt(i) as MaterialButton
                        btn.backgroundTintList = ContextCompat.getColorStateList(this, android.R.color.white)
                        btn.setTextColor(ContextCompat.getColor(this, android.R.color.darker_gray))
                    }
                }
                selectedOptions.add(letter)
                button.backgroundTintList = ContextCompat.getColorStateList(this, android.R.color.holo_blue_light)
                button.setTextColor(ContextCompat.getColor(this, android.R.color.white))
            }
            
            // Show submit button if we have the correct number of selections
            submitButton.visibility = if (selectedOptions.size == currentQuestion?.correct?.size) {
                View.VISIBLE
            } else {
                View.GONE
            }
            
            submitButton.setOnClickListener { submitAnswer() }
        } catch (e: Exception) {
            Log.e("QuizActivity", "Error handling option selection", e)
        }
    }

    private fun submitAnswer() {
        try {
            val correctAnswers = currentQuestion?.correct?.toSet() ?: emptySet()
            val isCorrect = selectedOptions == correctAnswers
            
            // Update all buttons
            for (i in 0 until optionsContainer.childCount) {
                val button = optionsContainer.getChildAt(i) as? MaterialButton
                if (button != null) {
                    val buttonLetter = button.text.toString().substringBefore(".")
                    when {
                        selectedOptions.contains(buttonLetter) -> {
                            // Selected option
                            button.backgroundTintList = ContextCompat.getColorStateList(this, 
                                if (correctAnswers.contains(buttonLetter)) android.R.color.holo_green_light 
                                else android.R.color.holo_red_light)
                            button.setTextColor(ContextCompat.getColor(this, android.R.color.white))
                        }
                        correctAnswers.contains(buttonLetter) -> {
                            // Correct answer (if not selected)
                            button.backgroundTintList = ContextCompat.getColorStateList(this, android.R.color.holo_green_light)
                            button.setTextColor(ContextCompat.getColor(this, android.R.color.white))
                        }
                    }
                    button.isEnabled = false
                }
            }

            if (isCorrect) {
                score++
                soundManager.playCorrectSound()
                resultText.text = "Correct!"
                resultText.setTextColor(ContextCompat.getColor(this, android.R.color.holo_green_dark))
            } else {
                soundManager.playIncorrectSound()
                resultText.text = "Incorrect"
                resultText.setTextColor(ContextCompat.getColor(this, android.R.color.holo_red_dark))
            }

            // Show explanation
            explanationText.text = currentQuestion?.explanation
            explanationCard.visibility = View.VISIBLE

            // Hide submit button and show next button
            submitButton.visibility = View.GONE
            nextButton.visibility = View.VISIBLE
            nextButton.setOnClickListener {
                currentQuestionIndex++
                showQuestion()
            }
        } catch (e: Exception) {
            Log.e("QuizActivity", "Error submitting answer", e)
        }
    }

    private fun updateProgress() {
        try {
            val progress = ((currentQuestionIndex + 1).toFloat() / questions.size) * 100
            ObjectAnimator.ofInt(progressIndicator, "progress", progress.toInt()).apply {
                duration = 500
                interpolator = AccelerateDecelerateInterpolator()
                start()
            }
        } catch (e: Exception) {
            Log.e("QuizActivity", "Error updating progress", e)
        }
    }

    private fun showQuizComplete() {
        try {
            val intent = Intent(this, QuizCompleteActivity::class.java).apply {
                putExtra("score", score)
                putExtra("total_questions", questions.size)
            }
            startActivity(intent)
            finish()
        } catch (e: Exception) {
            Log.e("QuizActivity", "Error showing quiz complete", e)
            showErrorDialog()
        }
    }

    private fun showErrorDialog() {
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.error))
            .setMessage(getString(R.string.error_message))
            .setPositiveButton(getString(R.string.ok)) { _, _ -> finish() }
            .setCancelable(false)
            .show()
    }

    private fun loadQuestions(): List<Question> {
        // First create the list of questions
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
            )
        )

        // Now return a shuffled list of questions, with shuffled options for each question
        return questions.map { question ->
            // Create a map of original option letters to shuffled options
            val originalOptions = question.options.associate { 
                it.substringBefore(".") to it.substringAfter(". ")
            }
            
            // Create a list of letters and shuffle them
            val letters = originalOptions.keys.toList()
            val shuffledLetters = letters.shuffled()
            
            // Create new shuffled options with correct letter prefixes
            val shuffledOptions = shuffledLetters.mapIndexed { index, originalLetter ->
                "${letters[index]}. ${originalOptions[originalLetter]}"
            }
            
            // Update correct answers to match new positions
            val newCorrectAnswers = question.correct.map { correctLetter ->
                letters[shuffledLetters.indexOf(correctLetter)]
            }
            
            Question(
                question.question,
                shuffledOptions,
                newCorrectAnswers,
                question.explanation,
                question.reference
            )
        }.shuffled()
    }

    override fun onDestroy() {
        super.onDestroy()
        soundManager.release()
    }
}

data class Question(
    val question: String,
    val options: List<String>,
    val correct: List<String>,
    val explanation: String,
    val reference: String
) 