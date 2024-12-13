package com.example.phishingdetector

import android.os.Bundle
import android.provider.Telephony
import android.util.Patterns
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.cardview.widget.CardView
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.jsoup.Jsoup
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection

class MainActivity : AppCompatActivity() {

    private lateinit var messagesTextView: TextView
    private lateinit var linkEditText: EditText
    private lateinit var checkLinkButton: Button
    private lateinit var resultTextView: TextView
    private lateinit var resultCardView: CardView
    private lateinit var scanMessagesButton: Button


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Initialize views HERE, AFTER setContentView
//        private lateinit var messagesTextView: TextView
//
//        messagesTextView = findViewById(R.id.messagesTextView)
        linkEditText = findViewById(R.id.linkEditText)
        checkLinkButton = findViewById(R.id.checkLinkButton)
        resultTextView = findViewById(R.id.resultTextView)
        resultCardView = findViewById(R.id.resultCardView)
        scanMessagesButton = findViewById(R.id.scanMessagesButton)


        scanMessagesButton.setOnClickListener {
            scanMessages()
        }

        checkLinkButton.setOnClickListener {
            val link = linkEditText.text.toString()
            if (link.isNotBlank()) {
                CoroutineScope(Dispatchers.IO).launch {
                    isPhishingLink(link, resultTextView, resultCardView)
                }
            } else {
                Toast.makeText(this, "Please enter a link", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun scanMessages() {
        val smsBuilder = StringBuilder()
        val cursor = contentResolver.query(Telephony.Sms.CONTENT_URI, null, null, null, null)

        if (cursor != null) {
            val messageCount = cursor.count
            if (cursor.moveToFirst()) {
                for (i in 0 until messageCount) {
                    val body = cursor.getString(cursor.getColumnIndexOrThrow(Telephony.Sms.BODY))
                    if (Patterns.WEB_URL.matcher(body).find()) {
                        smsBuilder.append("Message: ").append(body).append("\n")
                    }
                    cursor.moveToNext()
                }
            }
            cursor.close()
        }

        messagesTextView.text = smsBuilder.toString()
    }

    private suspend fun isPhishingLink(
        link: String,
        resultTextView: TextView,
        resultCardView: CardView
    ) = withContext(Dispatchers.IO) {
        var phishingScore = 0

        try {
            if (!Patterns.WEB_URL.matcher(link).matches()) {
                phishingScore += 30
                updateUI(resultTextView, resultCardView, "Invalid URL Format", phishingScore)
                return@withContext
            }

            val url = URL(link)
            val connection = url.openConnection()

            if (connection is HttpsURLConnection) {
                try {
                    connection.connect()
                    val certs = connection.serverCertificates
                    if (certs.isNullOrEmpty()) {
                        phishingScore += 40
                    } else {
                        val x509Cert = certs[0] as? X509Certificate
                        if (x509Cert == null) {
                            phishingScore += 40
                        } else {
                            try {
                                x509Cert.checkValidity()
                            } catch (e: Exception) {
                                phishingScore += 30
                            }
                        }
                    }
                } catch (e: Exception) {
                    phishingScore += 40
                }
            } else if (connection is HttpURLConnection) {
                if (link.startsWith("https")) phishingScore += 25
            }

            val httpConn = connection as? HttpURLConnection ?: run {
                updateUI(resultTextView, resultCardView, "Connection Error", 100)
                return@withContext
            }

            httpConn.connectTimeout = 5000
            httpConn.connect()

            val responseCode = httpConn.responseCode
            if (responseCode != HttpURLConnection.HTTP_OK) {
                phishingScore += 20
            }

            val doc = try {
                Jsoup.connect(link).get()
            } catch (e: Exception) {
                updateUI(resultTextView, resultCardView, "Error parsing page", 100)
                return@withContext
            }

            val suspiciousKeywords = listOf(
                "login", "signin", "bank", "account", "verify", "secure", "update", "free", "gift", "prize"
            )
            if (suspiciousKeywords.any {
                    link.contains(it, ignoreCase = true) || doc.title()
                        .contains(it, ignoreCase = true) || doc.body().text()
                        .contains(it, ignoreCase = true)
                }) {
                phishingScore += 15
            }

            if (doc.title().isNullOrBlank() || doc.title().length < 3) phishingScore += 10

            if (httpConn.url != url) phishingScore += 10
            if (doc.select("form[action*=login], form[action*=signin]").isNotEmpty()) phishingScore += 20

            try {
                val host = URL(link).host
                InetAddress.getByName(host)
                if (host.matches(Regex("^[0-9.]*$"))) phishingScore += 15
            } catch (e: Exception) {
            }

            val unusualTlds = listOf(
                ".top", ".xyz", ".online", ".site", ".bid", ".win", ".club", ".loan", ".work"
            )
            if (unusualTlds.any { link.endsWith(it, ignoreCase = true) }) phishingScore += 10

            val urlShorteners = listOf("bit.ly", "tinyurl.com", "goo.gl", "ow.ly")
            if (urlShorteners.any { link.contains(it, ignoreCase = true) }) phishingScore += 10

            updateUI(resultTextView, resultCardView, "Phishing Risk: $phishingScore%", phishingScore)

        } catch (e: Exception) {
            updateUI(resultTextView, resultCardView, "Error checking link", 100)
        }
    }

    private fun updateUI(
        resultTextView: TextView,
        resultCardView: CardView,
        message: String,
        score: Int
    ) {
        CoroutineScope(Dispatchers.Main).launch {
            resultTextView.text = message

            val backgroundColor = when {
                score >= 70 -> ContextCompat.getColor(
                    resultCardView.context,
                    android.R.color.holo_red_light
                )
                score >= 40 -> ContextCompat.getColor(
                    resultCardView.context,
                    android.R.color.holo_orange_light
                )
                else -> ContextCompat.getColor(
                    resultCardView.context,
                    android.R.color.holo_green_light
                )
            }
            resultCardView.setCardBackgroundColor(backgroundColor)
            resultCardView.visibility = View.VISIBLE
        }
    }
}