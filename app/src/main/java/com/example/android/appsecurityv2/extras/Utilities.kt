package com.example.android.appsecurityv2.extras

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.content.res.AssetManager
import android.graphics.Color
import android.os.Environment
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.example.android.appsecurityv2.appanalysis.AppAnalysisActivity
import com.example.android.appsecurityv2.models.AppItem
import com.google.android.material.snackbar.Snackbar
import org.apache.commons.io.FileUtils
import org.tensorflow.lite.Interpreter
import java.io.File
import java.io.FileInputStream
import java.nio.MappedByteBuffer
import java.nio.channels.FileChannel


class Utilities {

    companion object {

        const val STORAGE_PERMISSION_CODE = 1008

        fun checkPermission(activity: AppCompatActivity): Boolean {
            var permissionGranted = false

            if (ContextCompat.checkSelfPermission(
                    activity,
                    Manifest.permission.WRITE_EXTERNAL_STORAGE
                ) != PackageManager.PERMISSION_GRANTED) {
                if (ActivityCompat.shouldShowRequestPermissionRationale(
                        activity,
                        Manifest.permission.WRITE_EXTERNAL_STORAGE
                    )) {
                    val rootView: View = (activity as AppAnalysisActivity).window.decorView.findViewById(
                        android.R.id.content
                    )
                    Snackbar.make(rootView, "Storage permission required", Snackbar.LENGTH_LONG)
                        .setAction("Allow") {
                            ActivityCompat.requestPermissions(
                                activity,
                                arrayOf(Manifest.permission.WRITE_EXTERNAL_STORAGE),
                                STORAGE_PERMISSION_CODE
                            )
                        }
                        .setActionTextColor(Color.WHITE)
                        .show()
                } else {
                    ActivityCompat.requestPermissions(
                        activity,
                        arrayOf(Manifest.permission.WRITE_EXTERNAL_STORAGE),
                        STORAGE_PERMISSION_CODE
                    )
                }
            } else {
                permissionGranted = true
            }

            return permissionGranted
        }

        private fun checkExternalStorage(): Boolean {
            return Environment.getExternalStorageState() == Environment.MEDIA_MOUNTED
        }

        private fun getAppFolder(context: Context): File? {
            var file: File? = null
            if (checkExternalStorage()) {
                file = File(
                    context.getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS),
                    "ExtractedAPKs"
                )
                return file
            }
            return file
        }

        fun makeAppDir(context: Context) {
            val file = getAppFolder(context)
            if (file != null && !file.exists()) {
                file.mkdir()
            }
//            val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
//
//            }
        }

        private fun getApkFilePath(app: AppItem, context: Context): String {
            val randomNum = (Math.random()*1000).toInt()
            var fileName = getAppFolder(context)?.path + File.separator + randomNum + "_" + app.version + ".apk"
            logBTP("extracted location: $fileName")
            return fileName
        }

        fun extractApk(app: AppItem, context: Context): String {
            makeAppDir(context)
            var extracted = false
            val originalFile = File(app.appInfo.sourceDir)
            var extractedFilePath = getApkFilePath(app, context)
            val extractedFile: File = File(extractedFilePath)

            try {
                FileUtils.copyFile(originalFile, extractedFile)
//                val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
//                    type = "application/apk"
//                }
                extracted = true
                logBTP("${app.appName} successfully extracted!")
            } catch (e: Exception) {
                logBTP("problem - " + e.message)
            }
            if (!extracted) {
                extractedFilePath = "ERROR"
            }
            return extractedFilePath
        }

        private fun loadModelFile(assets: AssetManager, modelFilename: String): MappedByteBuffer {
            val fileDescriptor = assets.openFd(modelFilename)
            val inputStream = FileInputStream(fileDescriptor.fileDescriptor)
            val fileChannel = inputStream.channel
            val startOffset = fileDescriptor.startOffset
            val declaredLength = fileDescriptor.declaredLength
            return fileChannel.map(FileChannel.MapMode.READ_ONLY, startOffset, declaredLength)
        }

        private fun doInference(interpreter: Interpreter, input: FloatArray): Float {
            val output = Array(1) {
                FloatArray(
                    1
                )
            }
            interpreter.run(input, output)
            return output[0][0]
        }


        fun analyseApp(app: AppItem, context: Context): String {
            val inputData = app.mlModelInput
            val interpreter = Interpreter(loadModelFile(context.assets, "linear.tflite"), null)
            val output = doInference(interpreter, inputData)
            return output.toString()
        }

        fun updateBloomFilter(jsonString: String): Boolean {

            return true
        }

    }

}
