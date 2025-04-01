package com.ivanmp.myapplication

import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

/**
 * Activity to add SCOR PART 3 questions to the quiz database.
 * This activity can be launched to populate the SCOR PART 3 questions.
 */
class AddScorPart3QuestionsActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_add_scor_part3_questions)

        // Add the SCOR PART 3 questions
        val questions = ScorPart3Questions.getQuestions()
        QuizQuestions.addQuestions(QuestionCategory.SCOR_PART_3, questions)

        // Show a toast message
        Toast.makeText(
            this,
            "Added ${questions.size} questions to SCOR PART 3",
            Toast.LENGTH_LONG
        ).show()

        // Finish the activity
        finish()
    }
}
