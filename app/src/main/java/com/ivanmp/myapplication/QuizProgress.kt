package com.ivanmp.myapplication

import android.content.Context
import android.content.SharedPreferences
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken

class QuizProgress(context: Context) {
    private val prefs: SharedPreferences = context.getSharedPreferences("quiz_progress", Context.MODE_PRIVATE)
    private val gson = Gson()

    fun saveProgress(currentIndex: Int, score: Int, timeRemaining: Long) {
        prefs.edit().apply {
            putInt("current_index", currentIndex)
            putInt("score", score)
            putLong("time_remaining", timeRemaining)
            putLong("last_saved", System.currentTimeMillis())
            apply()
        }
    }

    fun loadProgress(): Triple<Int, Int, Long> {
        val currentIndex = prefs.getInt("current_index", 0)
        val score = prefs.getInt("score", 0)
        val timeRemaining = prefs.getLong("time_remaining", 0)
        return Triple(currentIndex, score, timeRemaining)
    }

    fun clearProgress() {
        prefs.edit().clear().apply()
    }

    fun hasProgress(): Boolean {
        return prefs.contains("current_index")
    }
} 