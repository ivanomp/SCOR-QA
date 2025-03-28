package com.ivanmp.myapplication

enum class QuestionCategory {
    SCOR_PART_1,
    SCOR_PART_2,
    SCOR_PART_3,
    SCOR_PART_4,
    SCOR_PART_5,
    SCOR_PART_6,
    SCOR_PART_7
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