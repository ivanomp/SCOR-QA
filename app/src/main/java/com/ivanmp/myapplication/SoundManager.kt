package com.ivanmp.myapplication

import android.content.Context
import android.media.MediaPlayer
import android.media.SoundPool
import android.os.Build
import android.util.Log
import com.ivanmp.myapplication.R

class SoundManager(context: Context) {
    private var soundPool: SoundPool? = null
    private var correctSound: Int = 0
    private var incorrectSound: Int = 0
    private var mediaPlayer: MediaPlayer? = null

    init {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                soundPool = SoundPool.Builder()
                    .setMaxStreams(2)
                    .build()
            } else {
                soundPool = SoundPool(2, android.media.AudioManager.STREAM_MUSIC, 0)
            }

            correctSound = soundPool?.load(context, R.raw.correct, 1) ?: 0
            incorrectSound = soundPool?.load(context, R.raw.incorrect, 1) ?: 0
        } catch (e: Exception) {
            Log.e("SoundManager", "Error initializing sound manager", e)
        }
    }

    fun playCorrectSound() {
        try {
            if (correctSound != 0) {
                soundPool?.play(correctSound, 1f, 1f, 1, 0, 1f)
            }
        } catch (e: Exception) {
            Log.e("SoundManager", "Error playing correct sound", e)
        }
    }

    fun playIncorrectSound() {
        try {
            if (incorrectSound != 0) {
                soundPool?.play(incorrectSound, 1f, 1f, 1, 0, 1f)
            }
        } catch (e: Exception) {
            Log.e("SoundManager", "Error playing incorrect sound", e)
        }
    }

    fun release() {
        try {
            soundPool?.release()
            soundPool = null
            mediaPlayer?.release()
            mediaPlayer = null
        } catch (e: Exception) {
            Log.e("SoundManager", "Error releasing sound manager", e)
        }
    }
} 