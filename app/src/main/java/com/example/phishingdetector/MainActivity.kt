package com.example.phishingdetector

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Bundle
import android.provider.Telephony
import android.util.Patterns
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.cardview.widget.CardView
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import kotlinx.coroutines.*
import org.jsoup.Jsoup
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection

private const val READ_SMS_PERMISSION_REQUEST_CODE = 101

class MainActivity : AppCompatActivity() {

    private lateinit var linkEditText: EditText
    private lateinit var checkLinkButton: Button
    private lateinit var clearLinkButton: Button
    private lateinit var resultTextView: TextView
    private lateinit var resultCardView: CardView
    private lateinit var scanMessagesButton: Button
    private lateinit var messagesRecyclerView: RecyclerView
    private lateinit var messageAdapter: MessageAdapter
    private lateinit var progressBar: ProgressBar

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        linkEditText = findViewById(R.id.linkEditText)
        checkLinkButton = findViewById(R.id.checkLinkButton)
        clearLinkButton = findViewById(R.id.clearLinkButton)
        resultTextView = findViewById(R.id.resultTextView)
        resultCardView = findViewById(R.id.resultCardView)
        scanMessagesButton = findViewById(R.id.scanMessagesButton)
        messagesRecyclerView = findViewById(R.id.messagesRecyclerView)
        progressBar = findViewById(R.id.progressBar)

        messagesRecyclerView.layoutManager = LinearLayoutManager(this)
        messageAdapter = MessageAdapter(mutableListOf()) { clickedLink ->
            linkEditText.setText(clickedLink)
            linkEditText.setSelection(clickedLink.length)
            checkLink()
        }
        messagesRecyclerView.adapter = messageAdapter

        clearLinkButton.setOnClickListener { linkEditText.text.clear() }
        checkLinkButton.setOnClickListener { checkLink() }
        scanMessagesButton.setOnClickListener { checkReadSmsPermission() }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == READ_SMS_PERMISSION_REQUEST_CODE) {
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                scanMessages()
            } else {
                Toast.makeText(this, "SMS permission is required.", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun checkReadSmsPermission() {
        if (ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.READ_SMS
            ) == PackageManager.PERMISSION_GRANTED
        ) {
            scanMessages()
        } else {
            ActivityCompat.requestPermissions(
                this,
                arrayOf(Manifest.permission.READ_SMS),
                READ_SMS_PERMISSION_REQUEST_CODE
            )
        }
    }

    private fun checkLink() {
        val link = linkEditText.text.toString()
        if (link.isNotBlank()) {
            progressBar.visibility = View.VISIBLE
            CoroutineScope(Dispatchers.IO).launch {
                isPhishingLink(link, resultTextView, resultCardView)
            }
        } else {
            Toast.makeText(this, "Please enter a link", Toast.LENGTH_SHORT).show()
        }
    }

    private fun scanMessages() {
        if (ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.READ_SMS
            ) == PackageManager.PERMISSION_GRANTED
        ) {
            val messageList = mutableListOf<String>()
            val cursor = contentResolver.query(Telephony.Sms.CONTENT_URI, null, null, null, null)

            cursor?.use {
                if (it.moveToFirst()) {
                    do {
                        val body = it.getString(it.getColumnIndexOrThrow(Telephony.Sms.BODY))
                        val matcher = Patterns.WEB_URL.matcher(body)
                        while (matcher.find()) {
                            messageList.add(matcher.group())
                        }
                    } while (it.moveToNext())
                }
            }
            messageAdapter.updateMessages(messageList)
        } else {
            Toast.makeText(this, "SMS permission is required.", Toast.LENGTH_SHORT).show()
        }
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
                withContext(Dispatchers.Main) {
                    updateUI(
                        resultTextView,
                        resultCardView,
                        "Invalid URL Format",
                        phishingScore
                    )
                }
                return@withContext
            }

            val url = URL(link)
            val connection = url.openConnection()

            if (connection is HttpsURLConnection) {
                try {
                    connection.connect()
                    val certs = connection.serverCertificates
                    phishingScore += when {
                        certs.isNullOrEmpty() -> 40
                        certs[0] as? X509Certificate == null -> 40
                        else -> try {
                            (certs[0] as X509Certificate).checkValidity()
                            0
                        } catch (e: Exception) {
                            30
                        }
                    }
                } catch (e: Exception) {
                    phishingScore += 40
                }
            } else if (connection is HttpURLConnection && link.startsWith("https")) phishingScore += 25

            val httpConn = connection as? HttpURLConnection
            if (httpConn == null) {
                withContext(Dispatchers.Main) {
                    updateUI(
                        resultTextView,
                        resultCardView,
                        "Connection Error",
                        100
                    )
                }
                return@withContext
            }

            httpConn.connectTimeout = 5000
            httpConn.connect()

            if (httpConn.responseCode != HttpURLConnection.HTTP_OK) phishingScore += 20

            val doc = try {
                Jsoup.connect(link).get()
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    updateUI(
                        resultTextView,
                        resultCardView,
                        "Error parsing page",
                        100
                    )
                }
                return@withContext
            }

            val suspiciousKeywords = listOf(
                "login",
                "signin",
                "bank",
                "account",
                "verify",
                "secure",
                "update",
                "free",
                "gift",
                "prize"
            )
            if (suspiciousKeywords.any {
                    link.contains(it, true) || doc.title().contains(it, true) || doc.body().text()
                        .contains(it, true)
                }) phishingScore += 15

            if (doc.title().isNullOrBlank() || doc.title().length < 3) phishingScore += 10
            if (httpConn.url != url) phishingScore += 10
            if (doc.select("form[action*=login], form[action*=signin]")
                    .isNotEmpty()
            ) phishingScore += 20

            try {
                val host = URL(link).host
                InetAddress.getByName(host)
                if (host.matches(Regex("^[0-9.]*$"))) phishingScore += 15
            } catch (e: Exception) {
            }

            val unusualTlds = listOf(
                ".top",
                ".xyz",
                ".online",
                ".site",
                ".bid",
                ".win",
                ".club",
                ".loan",
                ".work"
            )
            if (unusualTlds.any { link.endsWith(it, true) }) phishingScore += 10

            val urlShorteners = listOf("bit.ly", "tinyurl.com", "goo.gl", "ow.ly")
            if (urlShorteners.any { link.contains(it, true) }) phishingScore += 10

            withContext(Dispatchers.Main) {
                updateUI(
                    resultTextView,
                    resultCardView,
                    "Phishing Risk: $phishingScore%",
                    phishingScore
                )
            }
        } catch (e: Exception) {
            withContext(Dispatchers.Main) {
                updateUI(
                    resultTextView,
                    resultCardView,
                    "Error checking link: ${e.message}",
                    100
                )
            }
        } finally {
            withContext(Dispatchers.Main) { progressBar.visibility = View.GONE }
        }
    }

    private fun updateUI(
        resultTextView: TextView,
        resultCardView: CardView,
        message: String,
        score: Int
    ) {
        resultTextView.text = message
        progressBar.visibility = View.GONE
        val backgroundColor = when {
            score >= 70 -> ContextCompat.getColor(
                resultCardView.context,
                android.R.color.holo_red_light
            )

            score >= 40 -> ContextCompat.getColor(
                resultCardView.context,
                android.R.color.holo_orange_light
            )

            else -> ContextCompat.getColor(resultCardView.context, android.R.color.holo_green_light)
        }
        resultCardView.setCardBackgroundColor(backgroundColor)
        resultCardView.visibility = View.VISIBLE
    }

    private class MessageAdapter(
        private val messageList: MutableList<String>,
        private val onItemClick: (String) -> Unit
    ) : RecyclerView.Adapter<MessageAdapter.MessageViewHolder>() {

        class MessageViewHolder(
            itemView: View,
            private val onItemClick: (String) -> Unit,
            private val messageList: MutableList<String>
        ) : RecyclerView.ViewHolder(itemView) { // Added messageList back
            val linkTextView: TextView = itemView.findViewById(R.id.linkTextView);
            val context = itemView.context;

            init {
                itemView.setOnClickListener {
                    val position = adapterPosition;
                    if (position != RecyclerView.NO_POSITION) {
                        val link = messageList[position]; // Now we can access messageList here
                        onItemClick.invoke(link);

                        val clipboard =
                            context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager;
                        val clip = ClipData.newPlainText("Copied Link", link);
                        clipboard.setPrimaryClip(clip);

                        Toast.makeText(context, "Link copied to clipboard", Toast.LENGTH_SHORT)
                            .show();
                    }
                }
            }
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): MessageViewHolder {
            val itemView = LayoutInflater.from(parent.context)
                .inflate(R.layout.message_item_layout, parent, false);
            return MessageViewHolder(itemView, onItemClick, messageList); // Pass messageList here
        }

        override fun onBindViewHolder(holder: MessageViewHolder, position: Int) {
            holder.linkTextView.text = messageList[position];
        }

        override fun getItemCount() = messageList.size;

        fun updateMessages(newMessages: List<String>) {
            messageList.clear();
            messageList.addAll(newMessages);
            notifyDataSetChanged();
        }
    }
}