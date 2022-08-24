package com.example.android.appsecurityv2.extras
import android.app.Activity
import android.app.ProgressDialog
import android.content.pm.PackageManager
import android.net.Uri
import android.webkit.MimeTypeMap
import android.widget.Toast
import androidx.core.content.ContextCompat
import com.google.gson.Gson
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.asRequestBody
import org.json.JSONObject
import java.io.*
import java.math.BigDecimal
import java.util.concurrent.TimeUnit


class UploadUtility(activity: Activity) {
    var activity = activity;
    var dialog: ProgressDialog? = null
    internal var myExternalFile: File?=null
    // var serverUploadAPIEndpoint: String = "https://mal-detect1.herokuapp.com/upload/"
    // var serverUploadAPIEndpoint: String = "https://djangoservermha.herokuapp.com/upload/"
    // var serverUploadAPIEndpoint: String = "http://127.0.0.1:8000/upload/"
    var serverUploadAPIEndpoint: String = "http://172.16.29.42:8000/upload/"
//    var serverUploadAPIEndpoint: String = "http://192.168.59.23:8000/"

    val client = OkHttpClient.Builder()
        .connectTimeout(240, TimeUnit.SECONDS)
        .writeTimeout(240, TimeUnit.SECONDS)
        .readTimeout(240, TimeUnit.SECONDS)
        .callTimeout(240, TimeUnit.SECONDS)
        .build()

    // If we have source file path
    fun uploadFile(sourceFilePath: String, uploadedFileName: String? = null, boolean: Boolean? = false): Float {
        return uploadFile(File(sourceFilePath), uploadedFileName, boolean)
    }

    // If we have source file URI
    fun uploadFile(sourceFileUri: Uri, uploadedFileName: String? = null, boolean: Boolean? = false): Float {
        val pathFromUri = URIPathHelper().getPath(activity, sourceFileUri)
        return uploadFile(File(pathFromUri), uploadedFileName, boolean)
    }



    // If we have source file object
    fun uploadFile(sourceFile: File, uploadedFileName: String? = null, boolean: Boolean? = false): Float {
        var predictionValue: Float = 0f
        Thread {
            val mimeType = getMimeType(sourceFile);
            if (mimeType == null) {
                logBTP("Not able to get mime type")
                return@Thread
            }
            val fileName: String = uploadedFileName ?: sourceFile.name
            if (boolean == true) {
                toggleProgressDialog(false)
            } else {
                toggleProgressDialog(true)
            }
            try {
                val requestBody: RequestBody = MultipartBody.Builder().setType(MultipartBody.FORM)
                        .addFormDataPart(
                            "file",
                            fileName,
                            sourceFile.asRequestBody(mimeType.toMediaTypeOrNull())
                        )
                        .addFormDataPart("remark", "apk file")
                        .build()
                logBTP("Requesting at: $serverUploadAPIEndpoint")
                val request: Request = Request.Builder().url(serverUploadAPIEndpoint).post(
                    requestBody
                ).build()
                logBTP("Request Builded correctly")
                val response: Response = client.newCall(request).execute()
                logBTP("Respoonse Builded correctly")
                println(response.challenges())
                if (response.isSuccessful) {
                    logBTP("File upload successfully!")
                    val jsonString = Gson().toJson(response.body?.string())
                    val responseJSONString = jsonString.replace("\\", "")
                    val jsonObject = JSONObject(responseJSONString.substring(responseJSONString.indexOf("{"), responseJSONString.lastIndexOf("}") + 1))
                    predictionValue = BigDecimal.valueOf(jsonObject.getDouble("prediction")).toFloat()
                    val pkgJson = jsonObject.getString("package_name")
                    logBTP("pred: $predictionValue")
                   // val jsondbObject = JSONObject("/data/data/com.example.android.appsecurity/files/intial_database.json")
                    if (predictionValue > 0.5){

                      //val yourFilePath: String = activity.getFilesDir().toString() + "/" + "white_list.txt"
                       //val yourFile = File(yourFilePath)

                        if (ContextCompat.checkSelfPermission(activity, android.Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED ) {
                            val path = activity.getExternalFilesDir(null)
                            val letDirectory = File(path, "database")
                            if(!letDirectory.exists()) {
                                letDirectory.mkdirs()
                            }
                         val yourFile = File(letDirectory, "white_list.txt")

                            var text = ""
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
                                        stringBuilder.append(receiveString).append("\n")
                                    }
                                    //Close your InputStream and save stringBuilder as a String
                                    stringBuilder.append(pkgJson.toString()).append("\n")
                                    inputStream.close()

                                    text = stringBuilder.toString()
                                }
                            } catch (e: FileNotFoundException) {
                                //Log your error with Log.e
                            } catch (e: IOException) {
                                //Log your error with Log.e
                            }


                            var myJSONString: ByteArray = text.toByteArray()
                            try {
                                val fileOutputStream = FileOutputStream(yourFile)
                                fileOutputStream.write(myJSONString)
                                fileOutputStream.close()
                                //Log.d(TAG, "Written to file");
                            } catch (e: Exception) {
                                e.printStackTrace()
                            }

                            logBTP("file_path: $yourFile")

                        }else{
                            val permissions = arrayOf(android.Manifest.permission.WRITE_EXTERNAL_STORAGE, android.Manifest.permission.READ_EXTERNAL_STORAGE)
                            activity.requestPermissions(permissions,1)
                        }
                        logBTP("pkg_name: $pkgJson")
                    }else
                    {



                        if (ContextCompat.checkSelfPermission(activity, android.Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED ) {
                            val path = activity.getExternalFilesDir(null)
                            val letDirectory = File(path, "database")
                            if(!letDirectory.exists()) {
                                letDirectory.mkdirs()
                            }
                            val yourFile = File(letDirectory, "black_list.txt")

                            var text = ""
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
                                        stringBuilder.append(receiveString).append("\n")
                                    }
                                    //Close your InputStream and save stringBuilder as a String
                                    stringBuilder.append(pkgJson.toString()).append("\n")
                                    inputStream.close()

                                    text = stringBuilder.toString()
                                }
                            } catch (e: FileNotFoundException) {
                                //Log your error with Log.e
                            } catch (e: IOException) {
                                //Log your error with Log.e
                            }


                            var myJSONString: ByteArray = text.toByteArray()
                            try {
                                val fileOutputStream = FileOutputStream(yourFile)
                                fileOutputStream.write(myJSONString)
                                fileOutputStream.close()
                                //Log.d(TAG, "Written to file");
                            } catch (e: Exception) {
                                e.printStackTrace()
                            }

                            logBTP("file_path: $yourFile")

                        }else{
                            val permissions = arrayOf(android.Manifest.permission.WRITE_EXTERNAL_STORAGE, android.Manifest.permission.READ_EXTERNAL_STORAGE)
                            activity.requestPermissions(permissions,1)
                        }



//                   val yourFilePath: String = activity.getFilesDir().toString() + "/" + "black_list.txt"
//                       val yourFile = File(yourFilePath)
//
//                        var text = ""
//
//                        try {
//                            //Make an InputStream with your File in the constructor
//                            val inputStream: InputStream = FileInputStream(yourFile)
//                            val stringBuilder = StringBuilder()
//                            if (inputStream != null) {
//                                val inputStreamReader = InputStreamReader(inputStream)
//                                val bufferedReader = BufferedReader(inputStreamReader)
//                                var receiveString: String? = ""
//                                //Use a while loop to append the lines from the Buffered reader
//                                while (bufferedReader.readLine().also({ receiveString = it }) != null) {
//                                    stringBuilder.append(receiveString).append("\n")
//                                }
//                                //Close your InputStream and save stringBuilder as a String
//                                stringBuilder.append(pkgJson.toString()).append("\n")
//                                inputStream.close()
//
//                                text = stringBuilder.toString()
//                            }
//                        } catch (e: FileNotFoundException) {
//                            //Log your error with Log.e
//                        } catch (e: IOException) {
//                            //Log your error with Log.e
//                        }
//                        var myJSONString: ByteArray = text.toByteArray()
//                        try {
//                            val fileOutputStream = FileOutputStream(yourFile)
//                            fileOutputStream.write(myJSONString)
//                            fileOutputStream.close()
//                            //Log.d(TAG, "Written to file");
//                        } catch (e: Exception) {
//                            e.printStackTrace()
//                        }
//
//                        logBTP("pkg_name: $pkgJson")
                    }
                    showToast("File uploaded successfully!")
                } else {
                    logBTP("File upload failed!")
                    logBTP(response.message)
                    showToast("File uploading failed")
                }
            } catch (ex: Exception) {
                ex.printStackTrace()
                logBTP(ex.toString())
                ex.message?.let { logBTP(it) }
                logBTP("W:File upload failed")
                showToast("File uploading failed")
            }
            toggleProgressDialog(false)
        }.start()
        return predictionValue
    }

    // url = file path or whatever suitable URL you want.
    private fun getMimeType(file: File): String? {
        var type: String? = null
        val extension = MimeTypeMap.getFileExtensionFromUrl(file.path)
        if (extension != null) {
            type = MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension)
        }
        return type
    }

    private fun showToast(message: String) {
        activity.runOnUiThread {
            Toast.makeText(activity, message, Toast.LENGTH_LONG).show()
        }
    }

    private fun toggleProgressDialog(show: Boolean) {
        activity.runOnUiThread {
            if (show) {
                dialog = ProgressDialog.show(activity, "", "Uploading and Analysing apk...", true);
            } else {
                dialog?.dismiss();
            }
        }
    }
}