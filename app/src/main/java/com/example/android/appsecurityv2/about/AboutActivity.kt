package com.example.android.appsecurityv2.about

import android.os.Bundle
import android.text.Html
import androidx.appcompat.app.AppCompatActivity
import com.example.android.appsecurityv2.R
import kotlinx.android.synthetic.main.activity_about.*

class AboutActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_about)

        title = "About"

        val formattedAboutText = "<u><h1>Team</h1></u>" +
                "<br><h3>Supervisor:</h3>" +
                "<p><big>Dr. Somanath Tripathy</big></p>" +
                "<br><h3>Android and Web Developer:</h3>" +
                "<p><big>Divyanshu N Singh</big></p>" +
                "<br><h3>ML Developer:</h3>" +
                "<p><big>Narendra Singh</big></p>" +
                "<br><h3>Further Contribution:</h3>" +
                "<p><big>Abhishek Chopra</big></p>" +
                "<br><br><br><h3>IIT Patna</h3>"

        aboutTextView.text = Html.fromHtml(formattedAboutText, Html.FROM_HTML_MODE_COMPACT)
    }
}