package com.ivanmp.myapplication

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.card.MaterialCardView
import com.google.android.material.progressindicator.LinearProgressIndicator

class QuizPartsActivity : AppCompatActivity() {
    private lateinit var recyclerView: RecyclerView
    private lateinit var adapter: QuizPartsAdapter
    private lateinit var totalProgressIndicator: LinearProgressIndicator
    private lateinit var totalScoreText: TextView
    private lateinit var totalStatusText: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_quiz_parts)

        recyclerView = findViewById(R.id.partsRecyclerView)
        totalProgressIndicator = findViewById(R.id.totalProgressIndicator)
        totalScoreText = findViewById(R.id.totalScoreText)
        totalStatusText = findViewById(R.id.totalStatusText)

        adapter = QuizPartsAdapter(this) { category ->
            val intent = Intent(this, QuizActivity::class.java)
            intent.putExtra("category", category.name)
            startActivity(intent)
        }

        recyclerView.layoutManager = LinearLayoutManager(this)
        recyclerView.adapter = adapter

        updateTotalProgress()
    }

    private fun updateTotalProgress() {
        val totalProgress = QuizProgress.getTotalProgress(this)
        val totalScore = QuizProgress.getTotalScore(this)
        val isCompleted = QuizProgress.isQuizCompleted(this)

        totalProgressIndicator.progress = totalProgress
        totalScoreText.text = "Total Score: $totalScore%"
        totalStatusText.text = if (isCompleted) "Quiz Completed" else "In Progress"
    }

    override fun onResume() {
        super.onResume()
        updateTotalProgress()
        adapter.notifyDataSetChanged()
    }
} 