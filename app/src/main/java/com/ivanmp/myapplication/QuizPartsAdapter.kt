package com.ivanmp.myapplication

import android.content.Context
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.card.MaterialCardView
import com.google.android.material.progressindicator.LinearProgressIndicator

class QuizPartsAdapter(
    private val context: Context,
    private val onPartClick: (QuestionCategory) -> Unit
) : RecyclerView.Adapter<QuizPartsAdapter.PartViewHolder>() {

    class PartViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val card: MaterialCardView = view.findViewById(R.id.partCard)
        val titleText: TextView = view.findViewById(R.id.partTitleText)
        val descriptionText: TextView = view.findViewById(R.id.partDescriptionText)
        val progressIndicator: LinearProgressIndicator = view.findViewById(R.id.partProgressIndicator)
        val scoreText: TextView = view.findViewById(R.id.partScoreText)
        val statusText: TextView = view.findViewById(R.id.partStatusText)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): PartViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_quiz_part, parent, false)
        return PartViewHolder(view)
    }

    override fun onBindViewHolder(holder: PartViewHolder, position: Int) {
        val category = QuestionCategory.values()[position]
        val progress = QuizProgress.getPartProgress(context, category)
        val score = QuizProgress.getPartScore(context, category)
        val isCompleted = QuizProgress.isPartCompleted(context, category)

        holder.titleText.text = category.name.replace("_", " ")
        holder.descriptionText.text = getCategoryDescription(category)
        holder.progressIndicator.progress = progress
        holder.scoreText.text = "Score: $score%"
        holder.statusText.text = if (isCompleted) "Completed" else "Not Started"
        holder.statusText.setTextColor(
            holder.itemView.context.getColor(
                if (isCompleted) android.R.color.holo_green_dark
                else android.R.color.darker_gray
            )
        )

        holder.card.setOnClickListener { onPartClick(category) }
    }

    override fun getItemCount(): Int = QuestionCategory.values().size

    private fun getCategoryDescription(category: QuestionCategory): String {
        return when (category) {
            QuestionCategory.NETWORK_SECURITY_FUNDAMENTALS -> "Basic concepts and principles of network security"
            QuestionCategory.SECURITY_TECHNOLOGIES -> "Security technologies and their implementations"
            QuestionCategory.SECURITY_MANAGEMENT -> "Security management and monitoring"
            QuestionCategory.ADVANCED_SECURITY -> "Advanced security concepts and implementations"
        }
    }
} 