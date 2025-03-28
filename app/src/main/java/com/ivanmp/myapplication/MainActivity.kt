package com.ivanmp.myapplication

import android.content.Intent
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.view.animation.AnimationUtils
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import com.google.android.material.button.MaterialButton

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Set up toolbar
        val toolbar = findViewById<Toolbar>(R.id.toolbar)
        setSupportActionBar(toolbar)
        supportActionBar?.setDisplayShowTitleEnabled(false)

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

        // Set up start button
        findViewById<MaterialButton>(R.id.startButton).setOnClickListener {
            startActivity(Intent(this, QuizActivity::class.java))
        }
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.main_menu, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.action_about -> {
                startActivity(Intent(this, AboutActivity::class.java))
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }
}