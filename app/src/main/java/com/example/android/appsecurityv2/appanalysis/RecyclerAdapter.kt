package com.example.android.appsecurityv2.appanalysis

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.ImageView
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.example.android.appsecurityv2.R
import com.example.android.appsecurityv2.extras.UploadUtility
import com.example.android.appsecurityv2.extras.Utilities
import com.example.android.appsecurityv2.extras.logBTP
import com.example.android.appsecurityv2.models.AppItem
import com.google.android.material.snackbar.Snackbar
import kotlinx.android.synthetic.main.item_app.view.*
import org.jetbrains.anko.find

class RecyclerAdapter(
    private var titles: ArrayList<AppItem>,
    private var predAppList: java.util.ArrayList<Int>,
    context: Context
): RecyclerView.Adapter<RecyclerAdapter.ViewHolder>() {
    private val context = context
    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerAdapter.ViewHolder {
        val  v = LayoutInflater.from(parent.context).inflate(R.layout.scan_layout, parent, false)
        return ViewHolder(v)
    }

    @SuppressLint("SetTextI18n")
    override fun onBindViewHolder(holder: RecyclerAdapter.ViewHolder, position: Int) {
        holder.itemTitle.text = titles[position].appName
        holder.itemDetail.text
        if (titles[position].isInDatabase) {
            if (titles[position].isMalicious) {
                holder.itemDetail.text = "App found in database! Result: Malicious"
                holder.itemView.setBackgroundColor(Color.parseColor("#FF0000"))
            } else {
                holder.itemDetail.text = "App found in database: Result: Safe to use"
                holder.itemView.setBackgroundColor(Color.parseColor("#008000"))
            }
        } else {
            holder.itemDetail.text = "App not found in database. ${predAppList[position]}% suspicious"
            if (predAppList[position] > 50) {
                holder.itemView.setBackgroundColor(Color.parseColor("#FFCCCB"))
            } else {
                holder.itemView.setBackgroundColor(Color.parseColor("#FFFF00"))
            }
        }
        holder.itemImage.setImageDrawable(context.packageManager.getApplicationIcon(titles[position].appInfo))
    }

    override fun getItemCount(): Int {
        return titles.size
    }

    inner class ViewHolder(itemView: View): RecyclerView.ViewHolder(itemView) {
        var itemImage: ImageView
        var itemTitle: TextView
        var itemDetail: TextView
        private val mUninstallBtn: Button = itemView.find(R.id.uninstallBtn)
        private val mExtractBtn: Button = itemView.find(R.id.extractBtn)
        init {
            itemImage = itemView.findViewById(R.id.item_image)
            itemTitle = itemView.findViewById(R.id.item_title)
            itemDetail = itemView.findViewById(R.id.item_detail)
            mUninstallBtn.setOnClickListener {
                val uninstallIntent = Intent(Intent.ACTION_DELETE)
                uninstallIntent.data = Uri.parse("package:" + titles[adapterPosition].appPackageName)
                uninstallIntent.putExtra(Intent.EXTRA_RETURN_RESULT, true)
                context.startActivity(uninstallIntent)
            }

            mExtractBtn.setOnClickListener {
                if (Utilities.checkPermission(context as ScanActivity)) {
                    val extractedApkPath = Utilities.extractApk(titles[adapterPosition], context)
                    val rootView: View = context.window.decorView.findViewById(android.R.id.content)
                    if (extractedApkPath != "ERROR") {
                        logBTP("${titles[adapterPosition].appName} Extracted!")
                        logBTP("File Location: $extractedApkPath")
                        val predictionValue = UploadUtility(context).uploadFile(extractedApkPath)
                        logBTP("Prediction: $predictionValue")
                    } else {
                        Snackbar.make(
                            rootView,
                            "${titles[adapterPosition].appName} apk extraction failed",
                            Snackbar.LENGTH_LONG
                        ).show()
                    }
                }
            }
        }
    }
}