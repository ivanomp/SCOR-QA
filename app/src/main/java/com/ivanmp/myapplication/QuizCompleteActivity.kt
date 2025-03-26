package com.ivanmp.myapplication

import android.content.Intent
import android.os.Bundle
import android.view.animation.AnimationUtils
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton

class QuizCompleteActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_quiz_complete)

        val score = intent.getIntExtra("score", 0)
        val totalQuestions = intent.getIntExtra("total_questions", 0)
        val incorrectAnswers = totalQuestions - score

        // Animate score text
        findViewById<TextView>(R.id.scoreText).apply {
            text = "$score/$totalQuestions"
            startAnimation(AnimationUtils.loadAnimation(context, android.R.anim.fade_in))
        }

        // Update correct answers count
        findViewById<TextView>(R.id.correctAnswersCount).apply {
            text = score.toString()
            startAnimation(AnimationUtils.loadAnimation(context, android.R.anim.fade_in))
        }

        // Update incorrect answers count
        findViewById<TextView>(R.id.incorrectAnswersCount).apply {
            text = incorrectAnswers.toString()
            startAnimation(AnimationUtils.loadAnimation(context, android.R.anim.fade_in))
        }

        // Set feedback text based on score
        findViewById<TextView>(R.id.feedbackText).apply {
            text = when {
                score == totalQuestions -> "Perfect! You're a network security expert!"
                score >= totalQuestions * 0.8 -> "Great job! You have a solid understanding of network security."
                score >= totalQuestions * 0.6 -> "Good effort! Keep learning to improve your knowledge."
                else -> "Keep practicing! Network security concepts take time to master."
            }
            startAnimation(AnimationUtils.loadAnimation(context, android.R.anim.fade_in))
        }

        // Set up restart button
        findViewById<MaterialButton>(R.id.restartButton).setOnClickListener {
            startActivity(Intent(this, MainActivity::class.java))
            finish()
        }

        // Set up share button
        findViewById<MaterialButton>(R.id.shareButton).setOnClickListener {
            val shareIntent = Intent().apply {
                action = Intent.ACTION_SEND
                type = "text/plain"
                putExtra(Intent.EXTRA_TEXT, "I scored $score out of $totalQuestions on the Network Security Quiz!")
            }
            startActivity(Intent.createChooser(shareIntent, "Share your score"))
        }
    }

    override fun onBackPressed() {
        // Go back to MainActivity instead of previous question
        startActivity(Intent(this, MainActivity::class.java))
        finish()
    }
} 