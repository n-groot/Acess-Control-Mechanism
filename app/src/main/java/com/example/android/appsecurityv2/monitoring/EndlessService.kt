package com.example.android.appsecurityv2.monitoring

import android.app.*
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.hardware.camera2.CameraManager
import android.media.AudioManager
import android.media.AudioRecordingConfiguration
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.os.SystemClock
import android.widget.Toast
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.example.android.appsecurityv2.MainActivity
import com.example.android.appsecurityv2.R
import com.example.android.appsecurityv2.appanalysis.ScanActivity
import com.example.android.appsecurityv2.extras.Utilities
import com.example.android.appsecurityv2.extras.logBTP
import com.example.android.appsecurityv2.models.AppItem
import com.google.common.hash.BloomFilter
import com.google.common.hash.Funnels
import org.json.JSONObject
import java.io.*
import java.nio.charset.Charset
import java.util.*


class EndlessService : Service() {

    private var wakeLock: PowerManager.WakeLock? = null
    private var isServiceStarted = false
    // Notification
    private val NOTIFICATION_CHANNEL_ID = "BTP_APP_SERVICE_CHANNEL"
    private val NOTIFICATION_CHANNEL_NAME = "BTP app service notification channel"
    private val NOTIFICATION_ID = 0
    private var Notification_id_cnt = 1
    // Camera Manager
    private var cameraManager: CameraManager? = null
    private var cameraTracker: CameraManager.AvailabilityCallback? = null
    // Audio Manager
    private var audioManager: AudioManager? = null
    private var audioTracker: AudioManager.AudioRecordingCallback? = null

    override fun onBind(intent: Intent?): IBinder? {
        logBTP("Some component wants to bind with the service")
        // We don't provide binding, so return null
        return null
    }

    override fun onCreate() {
        super.onCreate()
        logBTP("Service has been created!")
        createNotificationChannel()
        val notification = createServiceNotification()
        startForeground(1, notification)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        logBTP("onStartCommand executed with startId: $startId")
        if (intent != null) {
            val action = intent.action
            logBTP("Using intent with action $action")
            when (action) {
                Actions.START.name -> startService()
                Actions.STOP.name -> stopService()
                else -> logBTP("Something wrong... No action in intent?")
            }
        } else {
            logBTP("Got null intent.. probably restarted by system")
        }
        // by returning this we make sure the service is restarted if the system kills the service
        return START_STICKY
    }

    override fun onTaskRemoved(rootIntent: Intent) {
        val restartServiceIntent = Intent(applicationContext, EndlessService::class.java).also {
            it.setPackage(packageName)
        };
        val restartServicePendingIntent: PendingIntent = PendingIntent.getService(this, 1, restartServiceIntent, PendingIntent.FLAG_ONE_SHOT);
        applicationContext.getSystemService(Context.ALARM_SERVICE);
        val alarmService: AlarmManager = applicationContext.getSystemService(Context.ALARM_SERVICE) as AlarmManager;
        alarmService.set(AlarmManager.ELAPSED_REALTIME, SystemClock.elapsedRealtime() + 1000, restartServicePendingIntent);
    }

    override fun onDestroy() {
        super.onDestroy()
        logBTP("Service has been destroyed!")
        Toast.makeText(this, "Service destroyed", Toast.LENGTH_SHORT).show()
        stopTrackingCamera()
        stopTrackingMicrophone()
    }

    /* ---------------------------- STARTING SERVICE ---------------------------- */
    private fun startService() {
        if (isServiceStarted) return
        setServiceState(this, ServiceState.STARTED)
        isServiceStarted = true
        logBTP("Starting foreground service")
        Toast.makeText(this, "Service Started", Toast.LENGTH_SHORT).show()

        // we need this lock so that our service does not get affected by Doze mode
        wakeLock = (getSystemService(Context.POWER_SERVICE) as PowerManager).run {
            newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "EndlessService::lock").apply {
                acquire()
            }
        }
        // Tracking Camera
        startTrackingCamera()
        // Tracking Microphone
        startTrackMicrophone()
        // Tracking Apps
        startTrackingApps()
    }

    /* --------------------------------- TRACKERS ------------------------------- */

    private fun startTrackingCamera() {
        logBTP("Alright.. trying to sense camera")
        cameraManager = getSystemService(Context.CAMERA_SERVICE) as CameraManager
        if (cameraManager != null) {
            cameraTracker = object: CameraManager.AvailabilityCallback() {
                override fun onCameraAvailable(cameraId: String) {
                    super.onCameraAvailable(cameraId)
//                    if (cameraId == "0")
//                        createNotification("Back camera is idle!")
//                    else
//                        createNotification("Front camera is idle!")
                }
                override fun onCameraUnavailable(cameraId: String) {
                    super.onCameraUnavailable(cameraId)
                    if (cameraId == "0")
                        createNotification("Back camera in use!")
                    else
                        createNotification("Front camera in use!")
                }
            }
            cameraManager!!.registerAvailabilityCallback(cameraTracker!!, null)
        } else {
            logBTP("cameraManager is null.. somehow")
        }
    }

    private fun stopTrackingCamera() {
        if (cameraManager != null && cameraTracker != null) {
            cameraManager!!.unregisterAvailabilityCallback(cameraTracker!!)
        }
    }

    private fun startTrackMicrophone() {
        logBTP("Alright.. trying to sense microphone")
        audioManager = getSystemService(Context.AUDIO_SERVICE) as AudioManager
        if (audioManager != null) {
            audioTracker = object: AudioManager.AudioRecordingCallback() {
                private var isRecording: Boolean = false
                override fun onRecordingConfigChanged(configs: MutableList<AudioRecordingConfiguration>?) {
                    super.onRecordingConfigChanged(configs)
                    isRecording = !isRecording
                    if (isRecording) {
                        createNotification("Recording started!")
                    } else {
                        createNotification("Recording stopped!")
                    }
                }
            }
            audioManager!!.registerAudioRecordingCallback(audioTracker!!, null)
        } else {
            logBTP("audioManager is null.. somehow")
        }
    }

    private fun stopTrackingMicrophone() {
        if (audioManager != null && audioTracker != null) {
            audioManager!!.unregisterAudioRecordingCallback(audioTracker!!)
        }
    }

    private fun loadJSONFromAssets(fileName: String): String {
        var json: String? = null
        try {
            val inputStream = this.assets.open(fileName)
            val size = inputStream.available()
            val buffer = ByteArray(size)
            inputStream.read(buffer)
            inputStream.close()
            json = String(buffer)
        }
        catch (ex: IOException) {
            ex.printStackTrace()
            return "{}"
        }
        return json
    }
    private fun startTrackingApps() {
        val PERMISSION_DICT_ML_MODEL_FILENAME = "permissions_dict_for_ml_model.json"
        // Loading app permission input vector for ML Model 1 (ML Model 2 is in server)
        val mlModelInputJsonObject = JSONObject(loadJSONFromAssets(PERMISSION_DICT_ML_MODEL_FILENAME))
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

        val yourFile: String = this@EndlessService.getExternalFilesDir(filepath).toString() + "/" + "white_list.txt"

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

        val path = this@EndlessService.getExternalFilesDir(null)
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
        // Loading all packages in user's phone
        // Sorting the packages by name
        var packagesChecked = ArrayList<String>()
        var allPackages = packageManager.getInstalledPackages(0)
        val timer = Timer()
        timer.scheduleAtFixedRate(
            object : TimerTask() {
                override fun run() {
                    allPackages = packageManager.getInstalledPackages(0)
                    allPackages.forEach {
                        if (packageManager.getLaunchIntentForPackage(it.packageName) != null && !packagesChecked.contains(it.packageName)) {
                            var isInDatabase: Boolean = false
                            var isMalicious: Boolean = false
                            val mlModelInput =
                                FloatArray(2561) // Current Size of permissions_dict_for_ml_model.json (CHECK FILE IN ASSETS)

                            // FIRSTLY CHECK IN BLOOM FILTER
                            val isWhiteListed = whitelistedBloomFilter.mightContain(it.packageName)
                            val isBlackListed = blacklistedBloomFilter.mightContain(it.packageName)

                            if (isBlackListed || isWhiteListed) {
                                logBTP("${it.packageName} is in bloomfilter database!")
                                isInDatabase = true
                                if (isWhiteListed) {
                                    isMalicious = false
                                } else if (isBlackListed) {
                                    isMalicious = true
                                }
                            } else {
                                // USE ML MODEL TO SHOW SUSPICIOUS PERCENTAGE OF THE APP
                                val data = createHashMapWithAllFeaturesOfApp(mlModelInputJsonObject, it.packageName)
                                val iterator = mlModelInputJsonObject.keys()
                                var index = 0
                                while (iterator.hasNext()) {
                                    if (index >=2561) {  // Current Size of permissions_dict_for_ml_model.json (CHECK FILE IN ASSETS)
                                        break
                                    }
                                    val key = iterator.next()
                                    mlModelInput[index] = data[key]!!
                                    index += 1
                                }
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
                            // Suspicious show, with probability..
                            val analysisResult = Utilities.analyseApp(anApp, this@EndlessService)
                            val percentage = (analysisResult.toFloat() * 100F).toInt()
                            if (anApp.isInDatabase) {
                                if (anApp.isMalicious) {
                                    createNotification_new(anApp.appName + " is found in database " + " Safe to use :)")
                                } else {
                                    createNotification_new(anApp.appName + " is found in database " + " Malicious :(")
                                }
                            } else {
                                createNotification_new(anApp.appName + " is not found in database " + "$percentage% probability of being malicious")
                            }
                            packagesChecked.add(it.packageName)
                        }
                    }
                }
            },  //Set how long before to start calling the TimerTask (in milliseconds)
            0,  //Set the amount of time between each execution (in milliseconds)
            10000
        )
    }

    /* ---------------------------- STOPPING SERVICE ---------------------------- */
    private fun stopService() {
        if (!isServiceStarted) return
        logBTP("Stopping foreground service")
        Toast.makeText(this, "Service Stopped", Toast.LENGTH_SHORT).show()
        try {
            wakeLock?.let {
                if (it.isHeld) {
                    it.release()
                }
            }
            stopForeground(true)
            stopSelf()
        } catch (e: Exception) {
            logBTP("Error while stopping service: ${e.message}")
        }
        isServiceStarted = false
        setServiceState(this, ServiceState.STOPPED)
    }

    /* ---------------------------- CREATING NOTIFICATION ---------------------------- */

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                NOTIFICATION_CHANNEL_NAME,
                NotificationManager.IMPORTANCE_HIGH
            ).let {
                it.description = "Service channel"
                it.enableLights(true)
                it.lightColor = Color.RED
                it.enableVibration(true)
                it.vibrationPattern = longArrayOf(100, 200, 300, 400, 500, 400, 300, 200, 400)
                it
            }
            notificationManager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(msg: String) {
        // Tapping on notification will open our app
        val pendingIntent: PendingIntent = Intent(this, MainActivity::class.java).let { notificationIntent ->
            PendingIntent.getActivity(this, 0, notificationIntent, 0)
        }

        // Create the notification that you want to post on your notification channel
        val notification = NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("App Security")
            .setContentText(msg)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(pendingIntent)
            .build()

        // Create a notification manager
        val notificationManager = NotificationManagerCompat.from(this)

        notificationManager.notify(NOTIFICATION_ID, notification)
    }
    private fun createNotification_new(msg: String) {
        // Tapping on notification will open our app
        val pendingIntent: PendingIntent = Intent(this, ScanActivity::class.java).let { notificationIntent ->
            PendingIntent.getActivity(this, 0, notificationIntent, 0)
        }

        // Create the notification that you want to post on your notification channel
        val notification = NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("App Security")
            .setContentText(msg)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(pendingIntent)
            .build()

        // Create a notification manager
        val notificationManager = NotificationManagerCompat.from(this)

        notificationManager.notify(Notification_id_cnt++, notification)
    }

    private fun createServiceNotification(): Notification {
        // Tapping on notification will open our app
        val pendingIntent: PendingIntent = Intent(this, MainActivity::class.java).let { notificationIntent ->
            PendingIntent.getActivity(this, 0, notificationIntent, 0)
        }

        //val builder = NotificationCompat.Builder(this, notificationChannelId)
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) Notification.Builder(
            this,
            NOTIFICATION_CHANNEL_ID
        ) else Notification.Builder (this)

        return builder
            .setContentTitle("App Security")
            .setContentText("Monitoring your device")
            .setContentIntent(pendingIntent)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setTicker("Ticker text")
            .setPriority(Notification.PRIORITY_HIGH) // for under api 26 compatibility
            .build()
    }
    // Used in V1
    private fun createHashMapWithAllFeaturesOfApp(mlModelInputJsonObject: JSONObject, packageName: String?): HashMap<String, Float> {
        val data = HashMap<String, Float>()
        if (packageName == null)
            return data;
        // Getting permissions
        val permissions = packageManager.getPackageInfo(
            packageName,
            PackageManager.GET_PERMISSIONS
        ).requestedPermissions
        // Getting activities
        val packActivities = packageManager.getPackageInfo(
            packageName,
            PackageManager.GET_ACTIVITIES
        ).activities;
        // Getting services
        val packServices = packageManager.getPackageInfo(
            packageName,
            PackageManager.GET_SERVICES
        ).services;
        // Getting providers
        val packProviders = packageManager.getPackageInfo(
            packageName,
            PackageManager.GET_PROVIDERS
        ).providers;
        // Getting receivers
        val packReceivers = packageManager.getPackageInfo(
            packageName,
            PackageManager.GET_RECEIVERS
        ).receivers;

        var iterator: Iterator<String> = mlModelInputJsonObject.keys()
        while (iterator.hasNext()) {
            val key = iterator.next()
            data[key] = 0F
        }

        // Adding all features into HashMap
        if (permissions != null) {
            for (per in permissions) {
                if (per != null) {
                    if (data.containsKey(per)) {
                        data[per] = 1F
                    }
                }
            }
        }
        if (packActivities != null) {
            for (acts in packActivities) {
                if (acts != null) {
                    if (data.containsKey(acts.name)) {
                        data[acts.name] = 1F
                    }
                }
            }
        }
        if (packServices != null) {
            for (serv in packServices) {
                if (serv != null) {
                    if (data.containsKey(serv.name)) {
                        data[serv.name] = 1F
                    }
                }
            }
        }
        if (packProviders != null) {
            for (prov in packProviders) {
                if (prov != null) {
                    if (data.containsKey(prov.name)) {
                        data[prov.name] = 1F
                    }
                }
            }
        }
        if (packReceivers != null) {
            for (acts in packReceivers) {
                if (acts != null) {
                    if (data.containsKey(acts.name)) {
                        data[acts.name] = 1F
                    }
                }
            }
        }
        return data;
    }
}
