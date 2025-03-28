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

    private var currentQuestionIndex = 0
    private var score = 0
    private var questions = listOf<Question>()
    private var currentQuestion: Question? = null
    private var selectedOptions = setOf<String>()
    private var itemPlacements = mutableMapOf<String, String>() // item text to category
    private var soundManager: SoundManager? = null
    private var currentCorrectAnswers: Set<String> = setOf()  // Add this property to the class
    private var answeredQuestions = mutableListOf<AnsweredQuestion>()
    private var currentCategory: QuestionCategory? = null

    data class AnsweredQuestion(
        val questionIndex: Int,
        val question: Question,
        val selectedOptions: Set<String>,
        val itemPlacements: Map<String, String> = mapOf(),
        val isCorrect: Boolean = false,
        val isSkipped: Boolean = false
    )

    companion object {
        private const val QUESTION_LIMIT = 100 // Default number of questions per quiz
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        try {
            super.onCreate(savedInstanceState)
            setContentView(R.layout.activity_quiz)

            // Initialize views
            initializeViews()
            
            // Initialize sound manager
            soundManager = SoundManager(this)

            // Get questions based on intent extras
            val questionLimit = intent.getIntExtra("question_limit", QUESTION_LIMIT)
            val categoryName = intent.getStringExtra("category")
            
            Log.d("QuizActivity", "Question limit: $questionLimit")
            
            // Parse category from intent
            currentCategory = try {
                QuestionCategory.valueOf(categoryName ?: "")
            } catch (e: IllegalArgumentException) {
                null
            }
            
            if (currentCategory != null) {
                Log.d("QuizActivity", "Total questions available for ${currentCategory!!.name}: ${QuizQuestions.getTotalQuestions(currentCategory!!)}")
                questions = QuizQuestions.getRandomQuestions(currentCategory!!, questionLimit)
            } else {
                Log.e("QuizActivity", "Invalid category: $categoryName")
                showErrorDialog()
                return
            }
            
            Log.d("QuizActivity", "Questions loaded: ${questions.size}")

            // Show first question
            showQuestion()

            // Set up button click listeners
            previousButton.setOnClickListener {
                showPreviousQuestion()
            }

            skipButton.setOnClickListener {
                // Add current question to skipped questions list if not already answered
                if (!answeredQuestions.any { it.questionIndex == currentQuestionIndex }) {
                    currentQuestion?.let { question ->
                        answeredQuestions.add(AnsweredQuestion(
                            questionIndex = currentQuestionIndex,
                            question = question,
                            selectedOptions = setOf(),
                            isSkipped = true
                        ))
                    }
                }
                showNextQuestion()
            }

            nextButton.setOnClickListener {
                showNextQuestion()
            }

            submitButton.setOnClickListener {
                currentQuestion?.let { question ->
                    when (question) {
                        is Question.MultipleChoice -> submitMultipleChoiceAnswer(question)
                        is Question.DragAndDrop -> submitDragAndDropAnswer(question)
                    }
                }
            }
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
            questionImage = findViewById(R.id.questionImage)
            optionsContainer = findViewById(R.id.optionsContainer)
            dragDropContainer = findViewById(R.id.dragDropContainer)
            itemsContainer = findViewById(R.id.itemsContainer)
            categoriesContainer = findViewById(R.id.categoriesContainer)
            submitButton = findViewById(R.id.submitButton)
            explanationCard = findViewById(R.id.explanationCard)
            resultText = findViewById(R.id.resultText)
            explanationText = findViewById(R.id.explanationText)
            nextButton = findViewById(R.id.nextButton)
            previousButton = findViewById(R.id.previousButton)
            skipButton = findViewById(R.id.skipButton)

            // Configure PhotoView
            questionImage.apply {
                maximumScale = 5.0f  // Maximum zoom level
                minimumScale = 1.0f  // Minimum zoom level (original size)
                mediumScale = 3.0f   // Double-tap zoom level
            }
        } catch (e: Exception) {
            Log.e("QuizActivity", "Error initializing views", e)
            throw e
        }
    }

    private fun showQuestion() {
        try {
            if (currentQuestionIndex < questions.size) {
                currentQuestion = questions[currentQuestionIndex]
                selectedOptions = setOf()
                itemPlacements.clear()
                
                when (val question = currentQuestion) {
                    is Question.MultipleChoice -> {
                        optionsContainer.visibility = View.VISIBLE
                        dragDropContainer.visibility = View.GONE
                        showMultipleChoiceQuestion(question)
                    }
                    is Question.DragAndDrop -> {
                        optionsContainer.visibility = View.GONE
                        dragDropContainer.visibility = View.VISIBLE
                        showDragAndDropQuestion(question)
                    }
                    null -> throw IllegalStateException("Question cannot be null")
                }

                // Update question number
                questionNumberText.text = getString(R.string.question_number, currentQuestionIndex + 1, questions.size)

                // Update progress
                updateProgress()

                // Update button states
                previousButton.visibility = if (currentQuestionIndex > 0) View.VISIBLE else View.GONE
                skipButton.visibility = if (!answeredQuestions.any { 
                    it.questionIndex == currentQuestionIndex && !it.isSkipped 
                }) View.VISIBLE else View.GONE
                
                // Update next button text based on question state
                nextButton.text = when {
                    currentQuestionIndex == questions.size - 1 -> "Finish"
                    answeredQuestions.any { it.questionIndex == currentQuestionIndex } -> "Next"
                    else -> "Next"
                }
            } else {
                showQuizComplete()
            }
        } catch (e: Exception) {
            Log.e("QuizActivity", "Error showing question", e)
            showErrorDialog()
        }
    }

    private fun showMultipleChoiceQuestion(question: Question.MultipleChoice) {
        // Update question text with multiple answer indicator if needed
        val questionPrefix = if (question.correct.size > 1) {
            "(Choose ${question.correct.size})"
        } else ""
        questionText.text = "$questionPrefix ${question.question}"
        
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
                
                // Reset zoom level when showing new image
                questionImage.scale = 1.0f
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
        val newCorrectAnswers = question.correct.map { correctLetter ->
            val correctContent = originalOptions[correctLetter]?.substringAfter(". ")?.trim()
            letters[shuffledContents.indexOf(correctContent)].toString()
        }.toSet()

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
        questionText.text = question.question
        
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
        
        explanationCard.visibility = View.GONE
        nextButton.visibility = View.GONE
        submitButton.visibility = View.GONE

        // Clear containers
        itemsContainer.removeAllViews()
        categoriesContainer.removeAllViews()

        // Add draggable items
        question.items.forEach { item ->
            val itemCard = MaterialCardView(this).apply {
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply {
                    setMargins(8)
                }
                radius = TypedValue.applyDimension(
                    TypedValue.COMPLEX_UNIT_DIP,
                    8f,
                    resources.displayMetrics
                )
                elevation = TypedValue.applyDimension(
                    TypedValue.COMPLEX_UNIT_DIP,
                    4f,
                    resources.displayMetrics
                )
                setCardBackgroundColor(ContextCompat.getColor(context, android.R.color.white))
                tag = item // Store item text in tag

                val itemText = TextView(context).apply {
                    text = item
                    setPadding(32, 24, 32, 24)
                    setTextColor(ContextCompat.getColor(context, android.R.color.darker_gray))
                }
                addView(itemText)

                // Setup drag functionality
                setOnLongClickListener { view ->
                    val clipData = ClipData.newPlainText("item", item)
                    val shadow = View.DragShadowBuilder(view)
                    view.startDragAndDrop(clipData, shadow, view, 0)
                    true
                }
            }
            itemsContainer.addView(itemCard)
        }

        // Add category containers
        question.categories.forEach { category ->
            val categoryCard = MaterialCardView(this).apply {
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply {
                    setMargins(8)
                }
                radius = TypedValue.applyDimension(
                    TypedValue.COMPLEX_UNIT_DIP,
                    8f,
                    resources.displayMetrics
                )
                elevation = TypedValue.applyDimension(
                    TypedValue.COMPLEX_UNIT_DIP,
                    4f,
                    resources.displayMetrics
                )
                setCardBackgroundColor(ContextCompat.getColor(context, android.R.color.white))

                val categoryLayout = LinearLayout(context).apply {
                    orientation = LinearLayout.VERTICAL
                    layoutParams = LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT
                    )

                    // Category header
                    addView(TextView(context).apply {
                        text = category
                        setPadding(32, 24, 32, 24)
                        setTextColor(ContextCompat.getColor(context, android.R.color.white))
                        textSize = 16f
                        setBackgroundColor(ContextCompat.getColor(context, android.R.color.darker_gray))
                    })

                    // Drop area
                    addView(LinearLayout(context).apply {
                        orientation = LinearLayout.VERTICAL
                        layoutParams = LinearLayout.LayoutParams(
                            LinearLayout.LayoutParams.MATCH_PARENT,
                            LinearLayout.LayoutParams.WRAP_CONTENT
                        )
                        minimumHeight = TypedValue.applyDimension(
                            TypedValue.COMPLEX_UNIT_DIP,
                            56f,
                            resources.displayMetrics
                        ).toInt()
                        setBackgroundColor(ContextCompat.getColor(context, android.R.color.white))
                        tag = category // Store category name in tag

                        // Setup drop functionality
                        setOnDragListener { view, event ->
                            when (event.action) {
                                DragEvent.ACTION_DRAG_STARTED -> {
                                    event.clipDescription.hasMimeType(ClipDescription.MIMETYPE_TEXT_PLAIN)
                                }
                                DragEvent.ACTION_DRAG_ENTERED -> {
                                    view.setBackgroundColor(ContextCompat.getColor(context, android.R.color.darker_gray))
                                    true
                                }
                                DragEvent.ACTION_DRAG_LOCATION -> true
                                DragEvent.ACTION_DRAG_EXITED -> {
                                    view.setBackgroundColor(ContextCompat.getColor(context, android.R.color.white))
                                    true
                                }
                                DragEvent.ACTION_DROP -> {
                                    view.setBackgroundColor(ContextCompat.getColor(context, android.R.color.white))
                                    
                                    // Get the item being dragged
                                    val item = event.clipData.getItemAt(0).text.toString()
                                    val draggedView = event.localState as View
                                    
                                    // Remove from previous parent
                                    (draggedView.parent as? ViewGroup)?.removeView(draggedView)
                                    
                                    // Add to new category
                                    (view as LinearLayout).addView(draggedView)
                                    
                                    // Update item placement
                                    itemPlacements[item] = category
                                    checkAllItemsPlaced()
                                    true
                                }
                                DragEvent.ACTION_DRAG_ENDED -> {
                                    view.setBackgroundColor(ContextCompat.getColor(context, android.R.color.white))
                                    true
                                }
                                else -> false
                            }
                        }
                    })
                }
                addView(categoryLayout)
            }
            categoriesContainer.addView(categoryCard)
        }

        submitButton.visibility = View.VISIBLE
        submitButton.setOnClickListener { submitAnswer() }
    }

    private fun checkAllItemsPlaced() {
        val question = currentQuestion as? Question.DragAndDrop ?: return
        submitButton.visibility = if (itemPlacements.size == question.items.size) {
            View.VISIBLE
        } else {
            View.GONE
        }
    }

    private fun onOptionSelected(button: MaterialButton, letter: String) {
        try {
            val question = currentQuestion as? Question.MultipleChoice ?: return
            
            if (selectedOptions.contains(letter)) {
                // Deselect option
                selectedOptions = selectedOptions - letter
                button.backgroundTintList = ContextCompat.getColorStateList(this, android.R.color.white)
                button.setTextColor(ContextCompat.getColor(this, android.R.color.darker_gray))
            } else {
                // Select option
                if (currentCorrectAnswers.size == 1) {
                    // Single answer question - clear previous selection
                    selectedOptions = setOf()
                    for (i in 0 until optionsContainer.childCount) {
                        val btn = optionsContainer.getChildAt(i) as MaterialButton
                        btn.backgroundTintList = ContextCompat.getColorStateList(this, android.R.color.white)
                        btn.setTextColor(ContextCompat.getColor(this, android.R.color.darker_gray))
                    }
                }
                selectedOptions = selectedOptions + letter
                button.backgroundTintList = ContextCompat.getColorStateList(this, android.R.color.holo_blue_light)
                button.setTextColor(ContextCompat.getColor(this, android.R.color.white))
            }
            
            // Show submit button if we have the correct number of selections
            submitButton.visibility = if (selectedOptions.size == currentCorrectAnswers.size) {
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
            // Hide submit button immediately
            submitButton.visibility = View.GONE
            
            when (val question = currentQuestion) {
                is Question.MultipleChoice -> submitMultipleChoiceAnswer(question)
                is Question.DragAndDrop -> submitDragAndDropAnswer(question)
                null -> throw IllegalStateException("Question cannot be null")
            }
        } catch (e: Exception) {
            Log.e("QuizActivity", "Error submitting answer", e)
        }
    }

    private fun submitMultipleChoiceAnswer(question: Question.MultipleChoice) {
        val isCorrect = selectedOptions == currentCorrectAnswers
            
        // Update all buttons
        for (i in 0 until optionsContainer.childCount) {
            val button = optionsContainer.getChildAt(i) as? MaterialButton
            if (button != null) {
                val buttonLetter = button.text.toString().substringBefore(".")
                when {
                    selectedOptions.contains(buttonLetter) -> {
                        // Selected option
                        button.backgroundTintList = ContextCompat.getColorStateList(this, 
                            if (currentCorrectAnswers.contains(buttonLetter)) android.R.color.holo_green_light 
                            else android.R.color.holo_red_light)
                        button.setTextColor(ContextCompat.getColor(this, android.R.color.white))
                    }
                    currentCorrectAnswers.contains(buttonLetter) -> {
                        // Correct answer (if not selected)
                        button.backgroundTintList = ContextCompat.getColorStateList(this, android.R.color.holo_green_light)
                        button.setTextColor(ContextCompat.getColor(this, android.R.color.white))
                    }
                }
                button.isEnabled = false
            }
        }

        // Play sound and update score based on result
        if (isCorrect) {
            soundManager?.playCorrectSound()
            score++
        } else {
            soundManager?.playIncorrectSound()
        }

        // Show explanation
        showExplanation(question.explanation, question.reference, isCorrect)
    }

    private fun submitDragAndDropAnswer(question: Question.DragAndDrop) {
        // First check if all items have been placed
        if (itemPlacements.size != question.items.size) {
            // Not all items have been placed
            soundManager?.playIncorrectSound()
            showExplanation(
                "Please place all items into categories before submitting.",
                question.reference,
                false
            )
            return
        }

        // Check if all placements are correct
        var isCorrect = true
        question.items.forEach { item ->
            val placedCategory = itemPlacements[item]
            val correctCategory = question.correctMapping[item]
            
            if (placedCategory != correctCategory) {
                isCorrect = false
            }
        }

        // Play sound and update score based on result
        if (isCorrect) {
            soundManager?.playCorrectSound()
            score++
        } else {
            soundManager?.playIncorrectSound()
        }

        // Show explanation
        showExplanation(question.explanation, question.reference, isCorrect)
    }

    private fun showExplanation(explanation: String, reference: String, isCorrect: Boolean) {
        // Store the current question state
        currentQuestion?.let { question ->
            answeredQuestions.add(
                AnsweredQuestion(
                    questionIndex = currentQuestionIndex,
                    question = question,
                    selectedOptions = selectedOptions,
                    itemPlacements = itemPlacements.toMap(),
                    isCorrect = isCorrect
                )
            )
        }

        explanationCard.visibility = View.VISIBLE
        resultText.text = if (isCorrect) "Correct!" else "Incorrect"
        resultText.setTextColor(ContextCompat.getColor(this, 
            if (isCorrect) android.R.color.holo_green_dark 
            else android.R.color.holo_red_dark))
        
        // Format the explanation text with proper spacing and line breaks
        val formattedExplanation = StringBuilder().apply {
            append(explanation)
            append("\n\n")
            append("Reference: ")
            append(reference)
        }.toString()
        
        // Make URLs clickable
        val spannableString = SpannableString(formattedExplanation)
        val urlPattern = "(https?://\\S+)".toRegex()
        urlPattern.findAll(formattedExplanation).forEach { match ->
            val url = match.value
            val start = match.range.first
            val end = match.range.last + 1
            spannableString.setSpan(
                URLSpan(url),
                start,
                end,
                Spannable.SPAN_EXCLUSIVE_EXCLUSIVE
            )
        }

        // Set the text with clickable links
        explanationText.text = spannableString
        explanationText.movementMethod = LinkMovementMethod.getInstance()
        explanationText.setLinkTextColor(Color.BLUE)

        // Show and configure navigation buttons
        nextButton.apply {
            visibility = View.VISIBLE
            backgroundTintList = ContextCompat.getColorStateList(context, android.R.color.holo_blue_dark)
            setTextColor(ContextCompat.getColor(context, android.R.color.white))
            text = if (currentQuestionIndex < questions.size - 1) getString(R.string.next_question) else "Finish"
            isEnabled = true
        }

        previousButton.apply {
            visibility = if (currentQuestionIndex > 0) View.VISIBLE else View.GONE
            setOnClickListener { showPreviousQuestion() }
        }
        
        nextButton.setOnClickListener {
            if (currentQuestionIndex < questions.size - 1) {
                currentQuestionIndex++
                showQuestion()
            } else {
                showQuizComplete()
            }
        }
        
        // Scroll to show the explanation and buttons
        findViewById<NestedScrollView>(R.id.mainScrollView).post {
            findViewById<NestedScrollView>(R.id.mainScrollView).fullScroll(View.FOCUS_DOWN)
        }
    }

    private fun showPreviousQuestion() {
        if (currentQuestionIndex > 0) {
            currentQuestionIndex--
            val previousAnswer = answeredQuestions[currentQuestionIndex]
            
            // Restore the previous question state
            currentQuestion = previousAnswer.question
            selectedOptions = previousAnswer.selectedOptions
            itemPlacements = previousAnswer.itemPlacements.toMutableMap()
            
            // Show the question with previous answers
            when (val question = currentQuestion) {
                is Question.MultipleChoice -> {
                    optionsContainer.visibility = View.VISIBLE
                    dragDropContainer.visibility = View.GONE
                    showMultipleChoiceQuestion(question)
                    
                    // Restore button states
                    for (i in 0 until optionsContainer.childCount) {
                        val button = optionsContainer.getChildAt(i) as? MaterialButton
                        if (button != null) {
                            val buttonLetter = button.text.toString().substringBefore(".")
                            if (selectedOptions.contains(buttonLetter)) {
                                button.backgroundTintList = ContextCompat.getColorStateList(this, 
                                    if (previousAnswer.isCorrect) android.R.color.holo_green_light 
                                    else android.R.color.holo_red_light)
                                button.setTextColor(ContextCompat.getColor(this, android.R.color.white))
                            }
                            button.isEnabled = false
                        }
                    }
                }
                is Question.DragAndDrop -> {
                    optionsContainer.visibility = View.GONE
                    dragDropContainer.visibility = View.VISIBLE
                    showDragAndDropQuestion(question)
                    
                    // Restore item placements
                    itemPlacements.forEach { (item, category) ->
                        val itemView = findItemViewByText(item)
                        val categoryView = findCategoryViewByName(category)
                        if (itemView != null && categoryView != null) {
                            (itemView.parent as? ViewGroup)?.removeView(itemView)
                            (categoryView as LinearLayout).addView(itemView)
                        }
                    }
                }
                null -> {
                    // Handle null case
                    Log.e("QuizActivity", "Question is null in showPreviousQuestion")
                    showErrorDialog()
                }
            }
            
            // Show explanation
            val explanation = when (val question = currentQuestion) {
                is Question.MultipleChoice -> question.explanation
                is Question.DragAndDrop -> question.explanation
                null -> "Error: Question not found"
            }
            
            val reference = when (val question = currentQuestion) {
                is Question.MultipleChoice -> question.reference
                is Question.DragAndDrop -> question.reference
                null -> "Error: Question not found"
            }
            
            showExplanation(explanation, reference, previousAnswer.isCorrect)
        }
    }

    private fun findItemViewByText(text: String): View? {
        for (i in 0 until itemsContainer.childCount) {
            val view = itemsContainer.getChildAt(i)
            if (view is MaterialCardView && view.getChildAt(0) is TextView) {
                val textView = view.getChildAt(0) as TextView
                if (textView.text == text) {
                    return view
                }
            }
        }
        return null
    }

    private fun findCategoryViewByName(category: String): View? {
        for (i in 0 until categoriesContainer.childCount) {
            val categoryCard = categoriesContainer.getChildAt(i) as MaterialCardView
            val categoryLayout = categoryCard.getChildAt(0) as LinearLayout
            val headerText = categoryLayout.getChildAt(0) as TextView
            if (headerText.text == category) {
                return categoryLayout.getChildAt(1) // Return the drop area LinearLayout
            }
        }
        return null
    }

    private fun updateProgress() {
        val progress = ((currentQuestionIndex + 1) * 100f / questions.size).toInt()
        ObjectAnimator.ofInt(progressIndicator, "progress", progress).apply {
            duration = 300
            interpolator = AccelerateDecelerateInterpolator()
            start()
        }
    }

    private fun showQuizComplete() {
        val intent = Intent(this, QuizCompleteActivity::class.java).apply {
            putExtra("score", score)
            putExtra("total", questions.size)
            currentCategory?.let { putExtra("category", it.name) }
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

    private fun showNextQuestion() {
        if (currentQuestionIndex < questions.size - 1) {
            currentQuestionIndex++
            showQuestion()
        } else {
            showQuizComplete()
        }
    }
} 