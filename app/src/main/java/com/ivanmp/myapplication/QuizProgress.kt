package com.ivanmp.myapplication

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken

object QuizProgress {
    private const val PREFS_NAME = "quiz_progress"
    private const val KEY_COMPLETED_PARTS = "completed_parts"
    private const val KEY_PART_SCORE_PREFIX = "part_score_"
    private const val KEY_PART_PROGRESS_PREFIX = "part_progress_"

    private fun getPrefs(context: Context): SharedPreferences {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    fun getCompletedParts(context: Context): Set<QuestionCategory> {
        val prefs = getPrefs(context)
        val completedParts = prefs.getStringSet(KEY_COMPLETED_PARTS, emptySet()) ?: emptySet()
        return completedParts.mapNotNull { 
            try {
                QuestionCategory.valueOf(it)
            } catch (e: IllegalArgumentException) {
                null
            }
        }.toSet()
    }

    fun markPartCompleted(context: Context, category: QuestionCategory) {
        val prefs = getPrefs(context)
        val completedParts = getCompletedParts(context).toMutableSet()
        completedParts.add(category)
        prefs.edit {
            putStringSet(KEY_COMPLETED_PARTS, completedParts.map { it.name }.toSet())
        }
    }

    fun getPartScore(context: Context, category: QuestionCategory): Int {
        val prefs = getPrefs(context)
        return prefs.getInt("${KEY_PART_SCORE_PREFIX}${category.name}", 0)
    }

    fun setPartScore(context: Context, category: QuestionCategory, score: Int) {
        val prefs = getPrefs(context)
        prefs.edit {
            putInt("${KEY_PART_SCORE_PREFIX}${category.name}", score)
        }
    }

    fun getPartProgress(context: Context, category: QuestionCategory): Int {
        val prefs = getPrefs(context)
        return prefs.getInt("${KEY_PART_PROGRESS_PREFIX}${category.name}", 0)
    }

    fun setPartProgress(context: Context, category: QuestionCategory, progress: Int) {
        val prefs = getPrefs(context)
        prefs.edit {
            putInt("${KEY_PART_PROGRESS_PREFIX}${category.name}", progress)
        }
    }

    fun getTotalScore(context: Context): Int {
        val categories = QuestionCategory.values()
        if (categories.isEmpty()) return 0
        
        val totalScore = categories.sumOf { getPartScore(context, it) }
        return totalScore / categories.size
    }

    fun getTotalProgress(context: Context): Int {
        val categories = QuestionCategory.values()
        if (categories.isEmpty()) return 0
        
        val totalProgress = categories.sumOf { getPartProgress(context, it) }
        return totalProgress / categories.size
    }

    fun isPartCompleted(context: Context, category: QuestionCategory): Boolean {
        return getCompletedParts(context).contains(category)
    }

    fun isQuizCompleted(context: Context): Boolean {
        val categories = QuestionCategory.values()
        return categories.all { isPartCompleted(context, it) }
    }

    fun resetProgress(context: Context) {
        val prefs = getPrefs(context)
        prefs.edit {
            clear()
        }
    }
} 