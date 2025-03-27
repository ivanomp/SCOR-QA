package com.ivanmp.myapplication

enum class QuestionCategory {
    NETWORK_SECURITY_FUNDAMENTALS,
    SECURITY_TECHNOLOGIES,
    SECURITY_MANAGEMENT,
    ADVANCED_SECURITY
}

sealed class Question {
    data class MultipleChoice(
        val question: String,
        val options: List<String>,
        val correct: Set<String>,
        val explanation: String,
        val reference: String,
        val category: QuestionCategory,
        val imageResourceName: String? = null
    ) : Question()

    data class DragAndDrop(
        val question: String,
        val items: List<String>,
        val categories: List<String>,
        val correctMapping: Map<String, String>, // item to category mapping
        val explanation: String,
        val reference: String,
        val category: QuestionCategory,
        val imageResourceName: String? = null
    ) : Question()
}

data class DragItem(
    val text: String,
    var currentCategory: String? = null
) 