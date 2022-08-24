package com.example.android.appsecurityv2

import android.content.Intent
import android.os.Build
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import com.example.android.appsecurityv2.about.AboutActivity
import com.example.android.appsecurityv2.appanalysis.AppAnalysisActivity
import com.example.android.appsecurityv2.appanalysis.ScanActivity
import com.example.android.appsecurityv2.extras.UploadUtility
import com.example.android.appsecurityv2.extras.Utilities
import com.example.android.appsecurityv2.extras.logBTP
import com.example.android.appsecurityv2.models.AppItem
import com.example.android.appsecurityv2.monitoring.Actions
import com.example.android.appsecurityv2.monitoring.EndlessService
import com.example.android.appsecurityv2.monitoring.ServiceState
import com.example.android.appsecurityv2.monitoring.getServiceState
import com.google.common.hash.BloomFilter
import com.google.common.hash.Funnels
import kotlinx.android.synthetic.main.activity_main.*
import java.io.*
import java.nio.charset.Charset
import java.util.*

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        title = "App Security"

        btnStartMonitoring.setOnClickListener {
            logBTP("Start Monitoring button pressed")
            actionOnService(Actions.START)
        }

        btnStopMonitoring.setOnClickListener {
            logBTP("Start Monitoring button pressed")
            actionOnService(Actions.STOP)
        }

//        btnAppAnalysis.setOnClickListener {
//            logBTP("")
//            Intent(this, AppAnalysisActivity::class.java).also {
//                startActivity(it)
//            }
//        }

        btnAbout.setOnClickListener {
            Intent(this, AboutActivity::class.java).also {
                startActivity(it)
            }
        }
        btnScan.setOnClickListener {
            logBTP("Listening")
            val intent = Intent(this, ScanActivity::class.java)
            startActivity(intent)
        }

        automatedSync.setOnCheckedChangeListener { buttonView, isChecked ->
            if (isChecked) {
                actionOnSwitch(Actions.START)
            } else {
                actionOnSwitch(Actions.STOP)
            }
        }

    }

    private fun actionOnService(action: Actions) {
        if (getServiceState(this) == ServiceState.STOPPED && action == Actions.STOP) return
        Intent(this, EndlessService::class.java).also {
            it.action = action.name
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                Log.d("ForegroundService", "Starting service in >=26 mode")
                startForegroundService(it)
            } else {
                Log.d("ForegroundService", "Starting service in <26 mode")
                startService(it)
            }
        }
    }
    private fun actionOnSwitch(action: Actions) {
        if (action == Actions.STOP)   return
        var allPackages = packageManager.getInstalledPackages(0)
        val timer = Timer()
        timer.scheduleAtFixedRate(
            object : TimerTask() {
                override fun run() {
                    val filepath = "database"

                    val whitelistedBloomFilter =
                        BloomFilter.create<String>(
                            Funnels.stringFunnel(Charset.forName("UTF-8")),
                            8000,
                            0.001
                        )
                    val blacklistedBloomFilter =
                        BloomFilter.create<String>(
                            Funnels.stringFunnel(Charset.forName("UTF-8")),
                            7500,
                            0.001
                        )
                    val yourFile: String = this@MainActivity.getExternalFilesDir(filepath).toString() + "/" + "white_list.txt"
                    try {
                        //Make an InputStream with your File in the constructor
                        val inputStream: InputStream = FileInputStream(yourFile)
                        val stringBuilder = StringBuilder()
                        if (inputStream != null) {
                            val inputStreamReader = InputStreamReader(inputStream)
                            val bufferedReader = BufferedReader(inputStreamReader)
                            var receiveString: String? = ""
                            //Use a while loop to append the lines from the Buffered reader
                            while (bufferedReader.readLine().also({ receiveString = it }) != null) {
                                whitelistedBloomFilter.put(receiveString)
                            }
                            inputStream.close()
                        }
                    } catch (e: FileNotFoundException) {
                        //Log your error with Log.e
                    } catch (e: IOException) {
                        //Log your error with Log.e
                    }

                    val path = this@MainActivity.getExternalFilesDir(null)
                    val letDirectory = File(path, "database")
                    if(!letDirectory.exists()) {
                        letDirectory.mkdirs()
                    }
                    val yourFile1 = File(letDirectory, "black_list.txt")

                    try {
                        //Make an InputStream with your File in the constructor
                        val inputStream: InputStream = FileInputStream(yourFile1)
                        val stringBuilder = StringBuilder()
                        if (inputStream != null) {
                            val inputStreamReader = InputStreamReader(inputStream)
                            val bufferedReader = BufferedReader(inputStreamReader)
                            var receiveString1: String? = ""
                            //Use a while loop to append the lines from the Buffered reader
                            while (bufferedReader.readLine().also({ receiveString1 = it }) != null) {
                                blacklistedBloomFilter.put(receiveString1)
                            }
                            inputStream.close()
                        }
                    } catch (e: FileNotFoundException) {
                        //Log your error with Log.e
                    } catch (e: IOException) {
                        //Log your error with Log.e
                    }
                    val mlModelInput =
                        FloatArray(2561)
                    allPackages = packageManager.getInstalledPackages(0)
                    allPackages.forEach {
                        if (packageManager.getLaunchIntentForPackage(it.packageName) != null) {
                            var isInDatabase: Boolean = false
                            var isMalicious: Boolean = false
                            // FIRSTLY CHECK IN BLOOM FILTER
                            val isWhiteListed = whitelistedBloomFilter.mightContain(it.packageName)
                            val isBlackListed = blacklistedBloomFilter.mightContain(it.packageName)

                            if (isBlackListed || isWhiteListed) {
                                logBTP("${it.packageName} is in bloomfilter database!")
                                isInDatabase = true
                            }
                            val anApp = AppItem(
                                appInfo = it.applicationInfo,
                                appName = packageManager.getApplicationLabel(it.applicationInfo).toString(),
                                appPackageName = it.packageName,
                                version = it.versionName,
                                mlModelInput = mlModelInput,
                                isInDatabase = isInDatabase,
                                isMalicious = isMalicious
                            )
                            if (!isInDatabase) {
                                val extractedApkPath = Utilities.extractApk(anApp, this@MainActivity)
                                UploadUtility(this@MainActivity).uploadFile(extractedApkPath, boolean = true)
                            }
                        }
                    }
                }
            },  //Set how long before to start calling the TimerTask (in milliseconds)
            0,  //Set the amount of time between each execution (in milliseconds)
            1000000
        )
    }
}