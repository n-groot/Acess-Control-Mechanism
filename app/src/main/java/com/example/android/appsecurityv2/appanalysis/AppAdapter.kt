package com.example.android.appsecurityv2.appanalysis

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.text.Html
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.ImageButton
import androidx.recyclerview.widget.RecyclerView
import com.example.android.appsecurityv2.R
import com.example.android.appsecurityv2.extras.UploadUtility
import com.example.android.appsecurityv2.extras.Utilities
import com.example.android.appsecurityv2.extras.Utilities.Companion.analyseApp
//import com.example.android.appsecurity.extras.Utilities.Companion.analysePackage
import com.example.android.appsecurityv2.extras.logBTP
import com.example.android.appsecurityv2.models.AppItem
import com.google.android.material.snackbar.Snackbar
import kotlinx.android.synthetic.main.item_app.view.*
import org.jetbrains.anko.find


class AppAdapter(
    private var appList: ArrayList<AppItem>,
    private val context: Context
) : RecyclerView.Adapter<AppAdapter.AppViewHolder>() {

    var mItemClickListener: OnContextItemClickListener? = null

    init {
        mItemClickListener = context as AppAnalysisActivity
    }

    // Called when RecyclerView needs a new view holder. For ex: when user scrolls
    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): AppViewHolder {
        return AppViewHolder(
            LayoutInflater.from(context).inflate(R.layout.item_app, parent, false),
            context,
            appList
        )
    }

    // This fun binds data to our items. It takes data from appList and sets it to the
    // corresponding view. "holder" has access to the item view. "position" is the index
    // of the particular view currently being bind.
    override fun onBindViewHolder(holder: AppViewHolder, position: Int) {
        holder.itemView.apply {
            appIcon.setImageDrawable(context.packageManager.getApplicationIcon(appList[position].appInfo))
            appName.text = appList[position].appName
            appPackageName.text = appList[position].appPackageName
        }
    }

    // Returns how many items we have in our RecyclerView
    override fun getItemCount(): Int {
        return appList.size
    }

    // A view holder is used to hold the views (item_app.xml) of RecyclerView
    inner class AppViewHolder(itemView: View, context: Context, appList: List<AppItem>) : RecyclerView.ViewHolder(
        itemView
    ) {
        private val mAnalyseBtn: Button = itemView.find(R.id.analyseBtn)
        private val mExtractBtn: Button = itemView.find(R.id.extractBtn)
        private val mUninstallBtn: Button = itemView.find(R.id.uninstallBtn)
        private val mMenuBtn: ImageButton = itemView.find(R.id.menuBtn)

        init {
            (context as Activity).registerForContextMenu(mMenuBtn)

            mAnalyseBtn.setOnClickListener {

                val rootView: View = context.window.decorView.findViewById(android.R.id.content)

                if (appList[adapterPosition].isInDatabase) {
                    // Analysis result of the particular app is present in database (in json in assets)
                    if (appList[adapterPosition].isMalicious) {
                        val snack = Snackbar.make(
                            rootView,
                            "${appList[adapterPosition].appName} is a malicious app.",
                            Snackbar.LENGTH_LONG
                        )
                        // Red
                        snack.view.setBackgroundColor(Color.parseColor("#FF0000"))
                        snack.show()
                    } else {
                        val snack = Snackbar.make(
                            rootView,
                            "${appList[adapterPosition].appName} is a benign app.",
                            Snackbar.LENGTH_LONG
                        )
                        // Green
                        snack.view.setBackgroundColor(Color.parseColor("#228B22"))
                        snack.show()
                    }
                } else {
                    // Analysis to be done using ML Model 1 (permission based)
                    val analysisResult = analyseApp(appList[adapterPosition], context)
                    val percentage = (analysisResult.toFloat() * 100F).toInt()
                    if (percentage == 0) {
                        val snack = Snackbar.make(
                            rootView,
                            "${appList[adapterPosition].appName} is a benign app.",
                            Snackbar.LENGTH_LONG
                        )
                        // Green
                        snack.view.setBackgroundColor(Color.parseColor("#228B22"))
                        snack.show()
                    } else if (percentage <= 15) {
                        val snack = Snackbar.make(
                            rootView,
                            Html.fromHtml("<font color=\"#000000\">${appList[adapterPosition].appName} is a suspicious app with ${percentage}% probability of being malicious.</font>"),
                            Snackbar.LENGTH_LONG
                        )
                        // Green
                        snack.view.setBackgroundColor(Color.parseColor("#ffe65e"))
                        snack.show()
                    } else if (percentage in 16..30) {
                        val snack = Snackbar.make(
                            rootView,
                            Html.fromHtml("<font color=\"#000000\">${appList[adapterPosition].appName} is a suspicious app with ${percentage}% probability of being malicious.</font>"),
                            Snackbar.LENGTH_LONG
                        )
                        // Yellow
                        snack.view.setBackgroundColor(Color.parseColor("#FFD700"))
                        snack.show()
                    } else if (percentage in 31..50) {
                        val snack = Snackbar.make(
                            rootView,
                            "${appList[adapterPosition].appName} is a suspicious app with ${percentage}% probability of being malicious.",
                            Snackbar.LENGTH_LONG
                        )
                        // Red
                        snack.view.setBackgroundColor(Color.parseColor("#B22222"))
                        snack.show()
                    } else if(percentage > 50) {
                        val snack = Snackbar.make(
                            rootView,
                            "${appList[adapterPosition].appName} is a suspicious app with ${percentage}% probability of being malicious.",
                            Snackbar.LENGTH_LONG
                        )
                        // Dark Red
                        snack.view.setBackgroundColor(Color.parseColor("#8B0000"))
                        snack.show()
                    }
                }

            }

            mExtractBtn.setOnClickListener {
                if (Utilities.checkPermission(context as AppAnalysisActivity)) {
                    val extractedApkPath = Utilities.extractApk(appList[adapterPosition], context)
                    val rootView: View = context.window.decorView.findViewById(android.R.id.content)
                    if (extractedApkPath != "ERROR") {
                        logBTP("${appList[adapterPosition].appName} Extracted!")
                        logBTP("File Location: $extractedApkPath")
                        val predictionValue = UploadUtility(context).uploadFile(extractedApkPath)
//                        val arr = Files.readAllBytes(Paths.get(appList[adapterPosition].appInfo.sourceDir))
//                        for (i in 0..100) {
//                            logBTP("${arr[i]}")
//                        }
//                        logBTP("Bytecode len: ${arr.size}")
                        logBTP("Prediction: $predictionValue")
//                        Snackbar.make(
//                            rootView,
//                            "${appList[adapterPosition].appName} apk extracted successfully",
//                            Snackbar.LENGTH_LONG
//                        ).show()
                    } else {
                        Snackbar.make(
                            rootView,
                            "${appList[adapterPosition].appName} apk extraction failed",
                            Snackbar.LENGTH_LONG
                        ).show()
                    }
                }
            }

            mUninstallBtn.setOnClickListener {
                val uninstallIntent = Intent(Intent.ACTION_DELETE)
                uninstallIntent.data = Uri.parse("package:" + appList[adapterPosition].appPackageName)
                uninstallIntent.putExtra(Intent.EXTRA_RETURN_RESULT, true)
                context.startActivity(uninstallIntent)
            }

            mMenuBtn.setOnClickListener {
                mItemClickListener?.onItemClicked(appList[adapterPosition].appPackageName!!)
                context.openContextMenu(mMenuBtn)
                mMenuBtn.setOnCreateContextMenuListener { contextMenu, _, _ ->
                    context.menuInflater.inflate(R.menu.context_menu, contextMenu)
                }
            }

        }
    }

    interface OnContextItemClickListener {
        fun onItemClicked(packageName: String)
    }
}