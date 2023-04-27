package com.example.observerapp
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import kotlinx.coroutines.Runnable
import java.math.BigInteger
import com.google.android.gms.maps.OnMapReadyCallback
import android.os.Handler
import android.graphics.Color
import android.net.wifi.WifiManager
import android.os.StrictMode
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.widget.Button
import android.widget.TextView
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.security.*
import java.util.*
import javax.security.auth.x500.X500Principal
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.google.android.gms.maps.CameraUpdateFactory
import com.google.android.gms.maps.MapView
import kotlinx.coroutines.*
import com.google.android.gms.maps.GoogleMap
import com.google.android.gms.maps.model.*

//Predefine the drone's address and port for communication
class SoftOptions {
    var RemoteHost: String = "169.254.236.79"
    var RemotePort: Int = 8008
    constructor()
    init{}
}
val Settings = SoftOptions()

//The main observer class that manages the API calls, sockets, and map plotting.
open class MainActivity : AppCompatActivity(), OnMapReadyCallback {

    private lateinit var googleMap: MapView
    private lateinit var mMap: GoogleMap
    private lateinit var marker: Marker
    private val sim_positions = listOf( // Three test coordinates for simulation
        LatLng(51.619732, -3.879636),
        LatLng(51.6184709954468, -3.8783780508154106),
        LatLng(51.61935692553764, -3.8783402107361042)
    )
    private val tracer = PolylineOptions()
    private var position = 0
    private val keyPairName = "my_keys"
    private lateinit var keyPair: KeyPair

    val policy = StrictMode.ThreadPolicy.Builder().permitAll().build()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_map)
        StrictMode.setThreadPolicy(policy) // to allow for WiFi access

//        val threadWithRunnable = Thread(UdpListener(8008))
//        threadWithRunnable.start()

        val lookupButton = findViewById<Button>(R.id.button) // button that will take you to the look up activity
        lookupButton.setOnClickListener {
            val intent = Intent(this, LookupActivity::class.java)
            startActivity(intent)
        }


        googleMap = findViewById(R.id.mapView)
        googleMap.onCreate(savedInstanceState)
        googleMap.getMapAsync(this)
        val responseText = findViewById<TextView>(R.id.text1)
        val publickKeyButton = findViewById<Button>(R.id.button4)
        publickKeyButton.setOnClickListener {
            CoroutineScope(Dispatchers.IO).launch {
                withContext(Dispatchers.Main) {
                    responseText.text = getPublicKey().toString()
                }
            }
        }
        //test simulated data
        responseText.text = "{\n" +
                "        \"dynamic\" : {\n" +
                "            \"Location vector\" : [51.619732, -3.879636, 1.0001],\n" +
                "            \"Ground speed(mph)\" : 9,\n" +
                "            \"Angle\" : 38.21,\n" +
                "            \"Timestamp\" : \"20/03/2023 9:53AM\",\n" +
                "            \"Status\" : \"In operation\"\n" +
                "        },\n" +
                "        \"static\" : {\n" +
                "            \"UAS_ID\" : 999,\n" +
                "            \"Serial Number\" : '',\n" +
                "            \"Registry ID\" : ''\n" +
                "            }\n" +
                "    }"
        if (!keyPairExists()) {
            generateKeyPair()
        }

//        udpListener = UdpListener(Settings.RemotePort)
//        udpListener.listen { message ->
//            runOnUiThread {
//                // Update UI with received message
//                textView.text = message
//            }
//        }

//      initialise()
    }

    //Initialise the observer to register itself before going live.
    private fun initialise() {
        val symmetricKey = "kqck_jYhKxsLvzp0DxMXj9O8QnXFgqAKIQ6ukQACf50="
        val message = "this is a test message"
        val entityType = "observer"
//        val symmetricEncryption = SymmetricEncryption()
//        val encrypted = symmetricEncryption.encrypt(
//            plaintext = message,
//            secret = symmetricKey
//        )
//        print(encrypted)
//        val url = "http://169.254.236.79:8000/test/$encrypted"
//        val response = CoroutineScope(Dispatchers.Main).async {
//            makeRequest(url)
//        }
    }

    //Opens a socket to continously listen for UDP messages
    fun getMessages(){
        val client = Socket("169.254.236.79", 8008)

        val clientInPutStream = client.getInputStream()
        while(true) {
            var nextByte = clientInPutStream.read()
            val textView = findViewById<TextView>(R.id.text1)
            textView.text = nextByte.toChar().toString()
            println(nextByte.toChar().toString())
        }
    }

    //Gets the local IP address of the emulator/device
    fun getLocalIpAddress(context: Context): String? {
        try {
            val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            val wifiInfo = wifiManager.connectionInfo
            val ipAddress = wifiInfo.ipAddress

            // Convert the IP address from an integer to a string
            val ipBytes = byteArrayOf(
                (ipAddress and 0xff).toByte(),
                (ipAddress shr 8 and 0xff).toByte(),
                (ipAddress shr 16 and 0xff).toByte(),
                (ipAddress shr 24 and 0xff).toByte()
            )
            val inetAddress = InetAddress.getByAddress(ipBytes)
            return inetAddress.hostAddress
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    // Loads the Google maps and starts plotting the drone with traces and tags.
    override fun onMapReady(p0: GoogleMap) {
        //plotting first marker
        mMap = p0
        val droneImage = BitmapFactory.decodeResource(resources, R.drawable.drone) // loading the drone icon from drawables
        val smallDroneImage = Bitmap.createScaledBitmap(droneImage, 150, 150, false) // resizing the drone image
        marker = mMap.addMarker(MarkerOptions().position(sim_positions[0]).title("UAS_ID: 00001").snippet(("Status: Authorised | in operation")).anchor(0.5f, 0.5f).icon(
            BitmapDescriptorFactory.fromBitmap(smallDroneImage)))!!
        mMap.moveCamera(CameraUpdateFactory.newLatLngZoom(sim_positions[0],15f))
        mMap.mapType = GoogleMap.MAP_TYPE_SATELLITE
        //adding first tracer
        tracer.add(sim_positions[0])
        tracer.color(Color.argb(25, 255, 0, 0))
        tracer.width(10f)
        mMap.addPolyline(tracer)

        val handler = Handler()
        handler.postDelayed(object : Runnable{
            override fun run(){
                marker.position = sim_positions[position]

            tracer.add(sim_positions[position])
            mMap.addPolyline(tracer)

            position = (position + 1) % sim_positions.size

            handler.postDelayed(this, 1000)
        }
        }, 1000)
    }

    //To check if the public key pair already exists
    private fun keyPairExists(): Boolean {
        val publicKeyPair = KeyStore.getInstance("AndroidKeyStore")
        publicKeyPair.load(null)
        return publicKeyPair.containsAlias(keyPairName)
    }

    //Generates the public key pair
    private fun generateKeyPair() {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore")
        val parameterSpec: KeyGenParameterSpec = KeyGenParameterSpec.Builder(keyPairName,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY).run {
            setCertificateSerialNumber(BigInteger.valueOf(777))
            setCertificateSubject(X500Principal("CN=$keyPairName"))
            setDigests(KeyProperties.DIGEST_SHA256)
            setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            setCertificateNotBefore(Calendar.getInstance().time)
            setCertificateNotAfter(Calendar.getInstance().apply { add(Calendar.YEAR, 1) }.time)
            build()
        }
        keyPairGenerator.initialize(parameterSpec)
        keyPair = keyPairGenerator.generateKeyPair()
    }

    //Loads and returns the public key - for testing
    private fun getPublicKey(): PublicKey {
        val publicKeyPair = KeyStore.getInstance("AndroidKeyStore")
        publicKeyPair.load(null)
        val loadedKeyPair = publicKeyPair.getCertificate(keyPairName)
        println(loadedKeyPair.publicKey)
        return loadedKeyPair.publicKey
    }

    //Function that opens a UDP socket to receive information from any IP address but on certain port.
    open fun receiveUDP() {
        val buffer = ByteArray(2048)
        var socket: DatagramSocket? = null
        try {
            socket = DatagramSocket(Settings.RemotePort, InetAddress.getByName(Settings.RemoteHost))
            socket.broadcast = true
            val packet = DatagramPacket(buffer, buffer.size)
            socket.receive(packet)
            println("open fun receiveUDP packet received = " + packet.data)
            val textView = findViewById<TextView>(R.id.text1)
            textView.text = packet.data.toString()

        } catch (e: Exception) {
            println("open fun receiveUDP catch exception." + e.toString())
            e.printStackTrace()
        } finally {
            socket?.close()
        }
    }

    override fun onResume() {
        googleMap.onResume()
        super.onResume()
    }

    override fun onPause() {
        googleMap.onPause()
        super.onPause()
    }

    override fun onDestroy() {
        googleMap.onDestroy()
        super.onDestroy()
    }

    override fun onLowMemory() {
        googleMap.onLowMemory()
        super.onLowMemory()
    }
}

class UdpDataArrival: Runnable, MainActivity() {
    public override fun run() {
        println("${Thread.currentThread()} Runnable Thread Started.")
        while (true){
//            receiveUDP()
        }

    }
}


