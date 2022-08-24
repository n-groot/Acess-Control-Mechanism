package com.example.android.appsecurityv2.appanalysis

import android.content.pm.PackageManager
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.example.android.appsecurityv2.R
import com.example.android.appsecurityv2.extras.Utilities
import com.example.android.appsecurityv2.extras.logBTP
import com.example.android.appsecurityv2.models.AppItem
import com.google.common.hash.BloomFilter
import com.google.common.hash.Funnels
import kotlinx.android.synthetic.main.activity_scan.*
import org.json.JSONObject
import java.io.*
import java.nio.charset.Charset
import java.util.ArrayList
import java.util.HashMap
import java.util.*

class ScanActivity : AppCompatActivity() {
    private var layoutManager: RecyclerView.LayoutManager? = null
    private var adapter: RecyclerView.Adapter<RecyclerAdapter.ViewHolder>? = null
    private val filepath = "database"
    private val DATABASE_FILENAME = "initial_database.json"
    private val PERMISSION_DICT_ML_MODEL_FILENAME = "permissions_dict_for_ml_model.json"


    private var appList = ArrayList<AppItem>()
    private var predAppList = ArrayList<Int>()
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_scan)

        loadApps()

        layoutManager = LinearLayoutManager(this)

        recyclerView.layoutManager = layoutManager


        adapter = RecyclerAdapter(appList, predAppList, this)
        recyclerView.adapter = adapter
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
    private fun loadApps() {
            // Loading database containing whitelisted and blacklisted package names
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

            val yourFile: String = this@ScanActivity.getExternalFilesDir(filepath).toString() + "/" + "white_list.txt"


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
//                logBTP("Debug: file not found")
            } catch (e: IOException) {
                //Log your error with Log.e
//                logBTP("Debug: IO error")
            }

            val path = this@ScanActivity.getExternalFilesDir(null)
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

            // Loading app permission input vector for ML Model 1 (ML Model 2 is in server)
            val mlModelInputJsonObject = JSONObject(loadJSONFromAssets(PERMISSION_DICT_ML_MODEL_FILENAME))

            // Loading all packages in user's phone
            val allPackages = packageManager.getInstalledPackages(0)
            // Sorting the packages by name
            allPackages.sortWith((Comparator { lhs, rhs ->
                val i1 = packageManager.getApplicationLabel(lhs.applicationInfo).toString()
                val i2 = packageManager.getApplicationLabel(rhs.applicationInfo).toString()
                i1.compareTo(i2)
            }))

            allPackages.forEach {
                if (packageManager.getLaunchIntentForPackage(it.packageName) != null) {


                    var isInDatabase: Boolean = false
                    var isMalicious: Boolean = false

                    // FIRSTLY CHECK IN BLOOM FILTER
                    val isWhiteListed = whitelistedBloomFilter.mightContain(it.packageName)
                    val isBlackListed = blacklistedBloomFilter.mightContain(it.packageName)
                    val mlModelInput =
                        FloatArray(2561) // Current Size of permissions_dict_for_ml_model.json (CHECK FILE IN ASSETS)

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
                    println("Size is " + anApp.appName)
                    // Suspicious show, with probability..
                    val analysisResult = Utilities.analyseApp(anApp, this)
                    val percentage = (analysisResult.toFloat() * 100F).toInt()
                    appList.add(anApp)
                    predAppList.add(percentage)
                }

            }
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