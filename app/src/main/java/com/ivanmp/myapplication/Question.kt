package com.ivanmp.myapplication

sealed class Question {
    data class MultipleChoice(
        val question: String,
        val options: List<String>,
        val correct: List<String>,
        val explanation: String,
        val reference: String
    ) : Question()

    data class DragAndDrop(
        val question: String,
        val items: List<String>,
        val categories: List<String>,
        val correctMapping: Map<String, String>, // item to category mapping
        val explanation: String,
        val reference: String
    ) : Question()
}

data class DragItem(
    val text: String,
    var currentCategory: String? = null
) 