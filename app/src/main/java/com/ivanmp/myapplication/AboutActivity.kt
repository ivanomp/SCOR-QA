package com.ivanmp.myapplication

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import com.google.android.material.button.MaterialButton

class AboutActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_about)

        // Set up toolbar
        val toolbar = findViewById<Toolbar>(R.id.toolbar)
        setSupportActionBar(toolbar)
        supportActionBar?.apply {
            setDisplayHomeAsUpEnabled(true)
            setDisplayShowTitleEnabled(true)
            title = "About"
        }

        // Set app description
        findViewById<TextView>(R.id.appDescriptionText).text = """
            SCOR QA is a comprehensive quiz application designed to help users prepare for the Cisco SCOR (Implementing and Operating Cisco Security Core Technologies) certification exam.
            
            Features:
            • Multiple question types
            • Detailed explanations
            • Progress tracking
            • Performance analytics
            • Modern Material Design UI
        """.trimIndent()

        // Set author information
        findViewById<TextView>(R.id.authorNameText).text = "Ivan Perete"
        findViewById<TextView>(R.id.authorEmailText).text = "n3tworkn00b@gmail.com"

        // Set acknowledgments
        findViewById<TextView>(R.id.acknowledgmentsText).text = """
            Special thanks to:
            • Cisco for providing the certification materials
            • The open-source community for their valuable tools and libraries
            • All contributors and testers who helped improve this app
        """.trimIndent()

        // Set up email button
        findViewById<MaterialButton>(R.id.emailButton).setOnClickListener {
            val intent = Intent(Intent.ACTION_SENDTO).apply {
                data = Uri.parse("mailto:n3tworkn00b@gmail.com")
                putExtra(Intent.EXTRA_SUBJECT, "SCOR QA App Feedback")
            }
            startActivity(Intent.createChooser(intent, "Send Email"))
        }
    }

    override fun onSupportNavigateUp(): Boolean {
        onBackPressed()
        return true
    }
} 