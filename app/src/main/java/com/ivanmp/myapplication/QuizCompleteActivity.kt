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
        val total = intent.getIntExtra("total", 0)
        val incorrect = total - score

        // Update score text
        findViewById<TextView>(R.id.scoreText).apply {
            text = "$score/$total"
            startAnimation(AnimationUtils.loadAnimation(context, android.R.anim.fade_in))
        }

        // Update correct answers count
        findViewById<TextView>(R.id.correctAnswersCount).apply {
            text = score.toString()
            startAnimation(AnimationUtils.loadAnimation(context, android.R.anim.fade_in))
        }

        // Update incorrect answers count
        findViewById<TextView>(R.id.incorrectAnswersCount).apply {
            text = incorrect.toString()
            startAnimation(AnimationUtils.loadAnimation(context, android.R.anim.fade_in))
        }

        // Set feedback text based on score
        val feedbackText = findViewById<TextView>(R.id.feedbackText)
        val percentage = (score.toFloat() / total.toFloat()) * 100
        feedbackText.text = when {
            percentage >= 90 -> "Excellent! You have a strong understanding of network security!"
            percentage >= 70 -> "Great job! You have a good grasp of network security concepts."
            percentage >= 50 -> "Good effort! Keep studying to improve your network security knowledge."
            else -> "Keep practicing! Review the concepts and try again to improve your score."
        }

        // Set up restart button
        findViewById<MaterialButton>(R.id.restartButton).setOnClickListener {
            finish()
        }

        // Set up share button
        findViewById<MaterialButton>(R.id.shareButton).setOnClickListener {
            val shareIntent = Intent().apply {
                action = Intent.ACTION_SEND
                putExtra(Intent.EXTRA_TEXT, 
                    "I scored $score out of $total on the SCOR QA Quiz!")
                type = "text/plain"
            }
            startActivity(Intent.createChooser(shareIntent, "Share your score"))
        }
    }

    override fun onBackPressed() {
        super.onBackPressed()
        finish()
    }
} 