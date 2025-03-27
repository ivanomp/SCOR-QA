package com.ivanmp.myapplication

import android.content.Intent
import android.os.Bundle
import android.view.animation.AnimationUtils
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Animate title and description
        findViewById<TextView>(R.id.titleText).startAnimation(
            AnimationUtils.loadAnimation(this, android.R.anim.fade_in).apply {
                duration = 1000
            }
        )

        findViewById<TextView>(R.id.subtitleText).startAnimation(
            AnimationUtils.loadAnimation(this, android.R.anim.fade_in).apply {
                duration = 1000
                startOffset = 300
            }
        )

        findViewById<TextView>(R.id.updateDateText).startAnimation(
            AnimationUtils.loadAnimation(this, android.R.anim.fade_in).apply {
                duration = 1000
                startOffset = 400
            }
        )

        findViewById<TextView>(R.id.descriptionText).startAnimation(
            AnimationUtils.loadAnimation(this, android.R.anim.fade_in).apply {
                duration = 1000
                startOffset = 500
            }
        )

        // Set up start quiz button with animation
        findViewById<MaterialButton>(R.id.startButton).apply {
            startAnimation(AnimationUtils.loadAnimation(this@MainActivity, android.R.anim.fade_in).apply {
                duration = 1000
                startOffset = 1000
            })
            setOnClickListener {
                val intent = Intent(this@MainActivity, QuizActivity::class.java).apply {
                    putExtra("question_limit", QuizQuestions.getTotalQuestions())
                }
                startActivity(intent)
            }
        }
    }
}