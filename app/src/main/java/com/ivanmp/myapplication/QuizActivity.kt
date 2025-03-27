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
    private lateinit var nextButton: MaterialButton
    private lateinit var previousButton: MaterialButton
    private lateinit var skipButton: MaterialButton
    private lateinit var binding: ActivityQuizBinding
    private var currentQuestionIndex = 0
    private var score = 0
    private var questions = QuestionBank.questions
    private var currentQuestion: Question? = null
    private var selectedOptions = setOf<String>()
    private var itemPlacements = mutableMapOf<String, String>() // item text to category
    private var soundManager: SoundManager? = null
    private var currentCorrectAnswers: Set<String> = setOf()
    private var answeredQuestions = mutableListOf<AnsweredQuestion>()

    data class AnsweredQuestion(
        val questionIndex: Int,
        val question: Question,
        val selectedOptions: Set<String>,
        val itemPlacements: Map<String, String> = mapOf(),
        val isCorrect: Boolean = false,
        val isSkipped: Boolean = false
    )

    companion object {
        private const val QUESTION_LIMIT = 50 // Default number of questions per quiz
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityQuizBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        setupUI()
        showQuestion(currentQuestionIndex)
    }
    
    private fun setupUI() {
        binding.nextButton.setOnClickListener {
            if (currentQuestionIndex < questions.size - 1) {
                currentQuestionIndex++
                showQuestion(currentQuestionIndex)
            }
        }
        
        binding.previousButton.setOnClickListener {
            if (currentQuestionIndex > 0) {
                currentQuestionIndex--
                showQuestion(currentQuestionIndex)
            }
        }
        
        binding.skipButton.setOnClickListener {
            if (currentQuestionIndex < questions.size - 1) {
                currentQuestionIndex++
                showQuestion(currentQuestionIndex)
            }
        }
    }
    
    private fun showQuestion(index: Int) {
        val question = questions[index]
        currentQuestion = question
        
        // Update question number and progress
        binding.questionNumberText.text = "Question ${when(question) {
            is Question.MultipleChoice -> question.id
            is Question.DragAndDrop -> question.id
        }}"
        binding.progressIndicator.progress = ((index + 1) * 100) / questions.size
        
        // Show question text
        binding.questionText.text = when(question) {
            is Question.MultipleChoice -> question.text
            is Question.DragAndDrop -> question.text
        }
        
        // Show/hide previous button
        binding.previousButton.visibility = if (index > 0) View.VISIBLE else View.GONE
        
        // Update next button text for last question
        binding.nextButton.text = if (index == questions.size - 1) "Finish" else "Next"
        
        // Clear previous state
        binding.optionsContainer.visibility = View.GONE
        binding.dragDropContainer.visibility = View.GONE
        binding.explanationCard.visibility = View.GONE
        
        when (question) {
            is Question.MultipleChoice -> showMultipleChoiceQuestion(question)
            is Question.DragAndDrop -> showDragAndDropQuestion(question)
        }
    }
    
    private fun showMultipleChoiceQuestion(question: Question.MultipleChoice) {
        binding.optionsContainer.visibility = View.VISIBLE
        binding.dragDropContainer.visibility = View.GONE
        
        // Clear previous options
        binding.optionsContainer.removeAllViews()
        
        // Add options
        question.options.forEachIndexed { index, option ->
            val button = MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
                text = "${('A' + index)}. $option"
                textSize = 16f
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply {
                    setMargins(0, 0, 0, 16.dpToPx())
                }
                setOnClickListener {
                    checkAnswer(option, question.correctAnswer)
                }
            }
            binding.optionsContainer.addView(button)
        }
    }
    
    private fun showDragAndDropQuestion(question: Question.DragAndDrop) {
        binding.optionsContainer.visibility = View.GONE
        binding.dragDropContainer.visibility = View.VISIBLE
        
        // Implementation for drag and drop questions...
        // This will be implemented later
    }
    
    private fun checkAnswer(selectedAnswer: String, correctAnswer: String) {
        val question = currentQuestion as? Question.MultipleChoice ?: return
        binding.explanationCard.visibility = View.VISIBLE
        
        val isCorrect = selectedAnswer == correctAnswer
        
        binding.resultText.text = if (isCorrect) "Correct!" else "Incorrect"
        binding.resultText.setTextColor(getColor(if (isCorrect) R.color.success else R.color.error))
        
        // Show explanation
        val explanationText = buildString {
            append(question.explanation)
            if (!question.reference.isNullOrBlank()) {
                append("\n\nReference: ${question.reference}")
            }
        }
        binding.explanationText.text = explanationText
        
        // Show next button
        binding.nextButton.visibility = View.VISIBLE
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
} 