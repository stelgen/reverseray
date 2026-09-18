package dev.stelgen.reverseray

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import dev.stelgen.reverseray.core.RrpUri
import dev.stelgen.reverseray.service.TunnelService

/** Minimal dashboard: import config string, start/stop tunnel. */
class MainActivity : AppCompatActivity() {

    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        status = findViewById(R.id.status)
        val input = findViewById<EditText>(R.id.config_input)
        val btnStart = findViewById<Button>(R.id.btn_start)
        val btnStop = findViewById<Button>(R.id.btn_stop)

        // FLAG_SECURE: no screenshots on the config screen (token visible).
        window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)

        val prefs = getSharedPreferences("rrp", MODE_PRIVATE)
        input.setText(prefs.getString("last_uri", ""))

        btnStart.setOnClickListener {
            val uri = input.text.toString().trim()
            try {
                RrpUri.parse(uri) // validate
            } catch (e: Exception) {
                Toast.makeText(this, getString(R.string.bad_config, e.message), Toast.LENGTH_LONG).show()
                return@setOnClickListener
            }
            prefs.edit().putString("last_uri", uri).putBoolean("autostart", true).apply()
            val i = Intent(this, TunnelService::class.java)
            i.putExtra(TunnelService.EXTRA_URI, uri)
            if (android.os.Build.VERSION.SDK_INT >= 26) {
                startForegroundService(i)
            } else {
                startService(i)
            }
        }

        btnStop.setOnClickListener {
            prefs.edit().putBoolean("autostart", false).apply()
            stopService(Intent(this, TunnelService::class.java))
            status.text = getString(R.string.status_disconnected)
        }
    }
}
