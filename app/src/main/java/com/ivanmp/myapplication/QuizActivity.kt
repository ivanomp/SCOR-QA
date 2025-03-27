package com.ivanmp.myapplication

import android.animation.ObjectAnimator
import android.content.ClipData
import android.content.ClipDescription
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.text.Spannable
import android.text.SpannableString
import android.text.method.LinkMovementMethod
import android.text.style.URLSpan
import android.util.Log
import android.util.TypedValue
import android.view.DragEvent
import android.view.View
import android.view.ViewGroup
import android.view.animation.AccelerateDecelerateInterpolator
import android.view.animation.AnimationUtils
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.setMargins
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.progressindicator.LinearProgressIndicator
import androidx.core.widget.NestedScrollView
import com.github.chrisbanes.photoview.PhotoView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.ivanmp.myapplication.databinding.ActivityQuizBinding
import android.widget.Toast

class QuizActivity : AppCompatActivity() {
    private lateinit var progressIndicator: LinearProgressIndicator
    private lateinit var questionNumberText: TextView
    private lateinit var questionText: TextView
    private lateinit var questionImage: PhotoView
    private lateinit var optionsContainer: LinearLayout
    private lateinit var dragDropContainer: LinearLayout
    private lateinit var itemsContainer: LinearLayout
    private lateinit var categoriesContainer: LinearLayout
    private lateinit var submitButton: MaterialButton
    private lateinit var explanationCard: MaterialCardView
    private lateinit var resultText: TextView
    private lateinit var explanationText: TextView
    private lateinit var referenceText: TextView
    private lateinit var nextButton: MaterialButton
    private lateinit var previousButton: MaterialButton
    private lateinit var skipButton: MaterialButton
    private lateinit var binding: ActivityQuizBinding
    private var currentQuestionIndex = 0
    private var score = 0
    private var questions: List<Question> = emptyList()
    private var currentQuestion: Question? = null
    private var selectedOptions = setOf<String>()
    private var itemPlacements = mutableMapOf<String, String>() // item text to category
    private var soundManager: SoundManager? = null
    private var currentCorrectAnswers: Set<String> = setOf()
    private var answeredQuestions = mutableListOf<AnsweredQuestion>()
    private var selectedAnswer: String? = null

    data class AnsweredQuestion(
        val questionId: Int,
        val questionText: String,
        val selectedAnswer: String,
        val correctAnswer: String,
        val isCorrect: Boolean
    )

    companion object {
        private const val QUESTION_LIMIT = 50 // Default number of questions per quiz
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_quiz)

        // Initialize views
        questionText = findViewById(R.id.questionText)
        questionImage = findViewById(R.id.questionImage)
        optionsContainer = findViewById(R.id.optionsContainer)
        explanationCard = findViewById(R.id.explanationCard)
        explanationText = findViewById(R.id.explanationText)
        referenceText = findViewById(R.id.referenceText)
        nextButton = findViewById(R.id.nextButton)
        previousButton = findViewById(R.id.previousButton)
        submitButton = findViewById(R.id.submitButton)
        progressIndicator = findViewById(R.id.progressIndicator)

        // Get questions from intent
        val category = intent.getStringExtra("category") ?: "general"
        questions = QuestionBank.questions

        // Initialize quiz state
        currentQuestionIndex = 0
        score = 0
        selectedAnswer = null

        // Set up click listeners
        nextButton.setOnClickListener {
            if (currentQuestionIndex < questions.size - 1) {
                currentQuestionIndex++
                showQuestion(questions[currentQuestionIndex])
            } else {
                finishQuiz()
            }
        }

        previousButton.setOnClickListener {
            if (currentQuestionIndex > 0) {
                currentQuestionIndex--
                showQuestion(questions[currentQuestionIndex])
            }
        }

        submitButton.setOnClickListener {
            val currentQuestion = questions[currentQuestionIndex] as? Question.MultipleChoice
            if (currentQuestion != null && selectedAnswer != null) {
                checkAnswer(selectedAnswer!!, currentQuestion)
            }
        }

        // Show first question
        if (questions.isNotEmpty()) {
            showQuestion(questions[0])
        }
    }
    
    private fun setupUI() {
        binding.nextButton.setOnClickListener {
            if (currentQuestionIndex < questions.size - 1) {
                currentQuestionIndex++
                showQuestion(questions[currentQuestionIndex])
            }
        }
        
        binding.previousButton.setOnClickListener {
            if (currentQuestionIndex > 0) {
                currentQuestionIndex--
                showQuestion(questions[currentQuestionIndex])
            }
        }
        
        binding.skipButton.setOnClickListener {
            if (currentQuestionIndex < questions.size - 1) {
                currentQuestionIndex++
                showQuestion(questions[currentQuestionIndex])
            }
        }
    }
    
    private fun showQuestion(question: Question) {
        when (question) {
            is Question.MultipleChoice -> showMultipleChoiceQuestion(question)
            is Question.DragAndDrop -> showDragAndDropQuestion(question)
        }
    }
    
    private fun showMultipleChoiceQuestion(question: Question.MultipleChoice) {
        // Update question text
        questionText.text = question.text
        
        // Handle question image
        if (question.imageResourceName != null) {
            val imageResId = resources.getIdentifier(
                question.imageResourceName,
                "drawable",
                packageName
            )
            if (imageResId != 0) {
                questionImage.setImageResource(imageResId)
                questionImage.visibility = View.VISIBLE
            } else {
                questionImage.visibility = View.GONE
            }
        } else {
            questionImage.visibility = View.GONE
        }
        
        optionsContainer.removeAllViews()
        explanationCard.visibility = View.GONE
        nextButton.visibility = View.GONE
        submitButton.visibility = View.GONE

        // Animate question text
        val slideIn = AnimationUtils.loadAnimation(this, android.R.anim.slide_in_left)
        slideIn.duration = 500
        questionText.startAnimation(slideIn)

        // Create a map of original options to track correct answers
        val originalOptions = question.options.associateBy { it.substringBefore(".") }
        
        // Shuffle only the content, keeping letters in order
        val shuffledContents = question.options.map { it.substringAfter(". ").trim() }.shuffled()
        val letters = ('A'..'E').take(question.options.size)
        
        // Create new options with ordered letters but shuffled content
        val newOptions = letters.zip(shuffledContents).map { (letter, content) -> "$letter. $content" }
        
        // Create a mapping of new options to determine correct answers
        val newCorrectAnswers = setOf(question.correctAnswer.substringBefore("."))

        newOptions.forEach { option ->
            val letter = option.substringBefore(".")
            val text = option.substringAfter(". ").trim()
            
            val button = MaterialButton(this).apply {
                this.text = option
                isAllCaps = false
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
                setOnClickListener { onOptionSelected(this, letter) }
            }
            optionsContainer.addView(button)
            
            // Animate each option button
            val fadeIn = AnimationUtils.loadAnimation(this, android.R.anim.fade_in)
            fadeIn.duration = 500
            button.startAnimation(fadeIn)
        }

        // Store the new correct answers for checking later
        selectedOptions = setOf()
        currentCorrectAnswers = newCorrectAnswers

        // Ensure the question is visible by scrolling to top
        findViewById<NestedScrollView>(R.id.mainScrollView).smoothScrollTo(0, 0)
    }
    
    private fun showDragAndDropQuestion(question: Question.DragAndDrop) {
        binding.optionsContainer.visibility = View.GONE
        binding.dragDropContainer.visibility = View.VISIBLE
        
        // Implementation for drag and drop questions...
        // This will be implemented later
    }
    
    private fun checkAnswer(selectedAnswer: String, question: Question.MultipleChoice) {
        // Disable all option buttons
        for (i in 0 until optionsContainer.childCount) {
            val button = optionsContainer.getChildAt(i) as? MaterialButton
            button?.isEnabled = false
        }

        // Show explanation
        explanationText.text = question.explanation
        explanationCard.visibility = View.VISIBLE

        // Show reference if available
        if (question.reference != null) {
            referenceText.text = "Reference: ${question.reference}"
            referenceText.visibility = View.VISIBLE
        } else {
            referenceText.visibility = View.GONE
        }

        // Show next button
        nextButton.visibility = View.VISIBLE

        // Animate explanation card
        val slideIn = AnimationUtils.loadAnimation(this, android.R.anim.slide_in_left)
        slideIn.duration = 500
        explanationCard.startAnimation(slideIn)

        // Check if answer is correct
        val isCorrect = selectedAnswer == question.correctAnswer.substringBefore(".")
        if (isCorrect) {
            score++
            showToast("Correct!")
        } else {
            showToast("Incorrect. The correct answer was: ${question.correctAnswer.substringBefore(".")}")
        }

        // Update progress
        currentQuestionIndex++
        updateProgress()
    }
    
    private fun Int.dpToPx(): Int {
        return (this * resources.displayMetrics.density).toInt()
    }
    
    private fun showQuizComplete() {
        val intent = Intent(this, QuizCompleteActivity::class.java).apply {
            putExtra("score", score)
            putExtra("total", questions.size)
        }
        startActivity(intent)
        finish()
    }
    
    private fun showErrorDialog() {
        AlertDialog.Builder(this)
            .setTitle("Error")
            .setMessage("An error occurred. Please try again.")
            .setPositiveButton("OK") { _, _ -> finish() }
            .show()
    }

    private fun onOptionSelected(button: MaterialButton, selectedLetter: String) {
        // Deselect all buttons
        for (i in 0 until optionsContainer.childCount) {
            val optionButton = optionsContainer.getChildAt(i) as? MaterialButton
            optionButton?.setBackgroundColor(getColor(android.R.color.white))
            optionButton?.setTextColor(getColor(android.R.color.darker_gray))
        }

        // Select the clicked button
        button.setBackgroundColor(getColor(R.color.primary))
        button.setTextColor(getColor(android.R.color.white))

        // Show submit button
        submitButton.visibility = View.VISIBLE

        // Store selected answer
        selectedAnswer = selectedLetter
    }

    private fun finishQuiz() {
        val intent = Intent(this, QuizCompleteActivity::class.java).apply {
            putExtra("score", score)
            putExtra("totalQuestions", questions.size)
            putExtra("category", intent.getStringExtra("category"))
        }
        startActivity(intent)
        finish()
    }

    private fun updateProgress() {
        val progress = ((currentQuestionIndex + 1) * 100) / questions.size
        progressIndicator.progress = progress
        
        // Update question number text
        findViewById<TextView>(R.id.questionNumberText).text = "Question ${currentQuestionIndex + 1} of ${questions.size}"
        
        // Update navigation buttons
        previousButton.visibility = if (currentQuestionIndex > 0) View.VISIBLE else View.GONE
        nextButton.text = if (currentQuestionIndex == questions.size - 1) "Finish" else "Next"
    }

    private fun showToast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }
} 