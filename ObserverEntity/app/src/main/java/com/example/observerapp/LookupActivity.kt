package com.example.observerapp
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import androidx.appcompat.app.AppCompatActivity
import android.content.Context
import android.widget.TextView
import kotlinx.coroutines.CoroutineScope
import java.io.InputStreamReader
import kotlinx.coroutines.launch
import java.net.URL
import kotlinx.coroutines.Dispatchers
import java.net.HttpURLConnection
import kotlinx.coroutines.withContext
import java.io.BufferedReader


class LookupActivity : AppCompatActivity(){
    private val serverKey = "kqck_jYhKxsLvzp0DxMXj9O8QnXFgqAKIQ6ukQACf50=" //symmetric key for API <-> observer

    //Instantiates the lookup activty page
    override fun onCreate(savedInstanceState: Bundle?){
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_lookup)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)

        val sharedKeys = getSharedPreferences("app_prefs", Context.MODE_PRIVATE) // Load the SharedKeys
        sharedKeys.edit().putString(serverKey, "server_key").apply() // Store the symmetric key in SharedPreferences

        val searchEditText = findViewById<EditText>(R.id.searchstuff)
        val p2LookButton = findViewById<Button>(R.id.button3)
        val authEditText = findViewById<EditText>(R.id.authstuff)
        val pLookButton = findViewById<Button>(R.id.button2)
        val textView = findViewById<TextView>(R.id.textView2)

        pLookButton.setOnClickListener { // public lookup button listener
            val uasID = searchEditText.text.toString()
            if (uasID.isNotEmpty()) {
                CoroutineScope(Dispatchers.IO).launch {
                    val response = publicLookupRequest(uasID)
                    withContext(Dispatchers.Main) {
                        textView.text = response
                    }
                }
            }
        }

        p2LookButton.setOnClickListener { // private lookup button listener
            val uasID = searchEditText.text.toString()
            val authToken = authEditText.text.toString()
            if (uasID.isNotEmpty() and authToken.isNotEmpty()) {
                CoroutineScope(Dispatchers.IO).launch {
                    val response = privateLookupRequest(uasID, authToken)
                    withContext(Dispatchers.Main) {
                        textView.text = response
                    }
                }
            }
        }
    }

    //Function for making a public lookup get request to the server
    private fun publicLookupRequest(uasId: String): String {
        val url = URL("http://169.254.236.79:8000/public-lookup/$uasId")

        with(url.openConnection() as HttpURLConnection) {

            println("Response : $responseCode")
            BufferedReader(InputStreamReader(inputStream)).use {
                val response = StringBuffer()

                var inputLine = it.readLine()
                while (inputLine != null) {
                    response.append(inputLine)
                    inputLine = it.readLine()
                }
                return response.toString()
            }
        }
    }

    //Function for making a private lookup get request to the server
    private fun privateLookupRequest(uasId: String, auth: String): String {
        val url = URL("http://169.254.236.79:8000/private-lookup/$uasId,$auth")

        with(url.openConnection() as HttpURLConnection) {

            println("Response : $responseCode")
            BufferedReader(InputStreamReader(inputStream)).use {
                val response = StringBuffer()

                var inputLine = it.readLine()
                while (inputLine != null) {
                    response.append(inputLine)
                    inputLine = it.readLine()
                }
                return response.toString()
            }
        }
    }

    //Allows the activity to have a back button
    override fun onSupportNavigateUp(): Boolean {
        finish()
        return true
    }
}