package com.example.android.appsecurityv2.models

import android.content.pm.ApplicationInfo

// Define what belongs to an item of RecyclerView (used to show list of app)
data class AppItem (
    val appInfo: ApplicationInfo,
    val appName: String,
    val appPackageName: String? = "",
    val version: String? = "",
    val mlModelInput: FloatArray,
    val isInDatabase: Boolean = false,
    val isMalicious: Boolean = false
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AppItem

        if (appInfo != other.appInfo) return false
        if (appName != other.appName) return false
        if (appPackageName != other.appPackageName) return false
        if (version != other.version) return false
        if (!mlModelInput.contentEquals(other.mlModelInput)) return false
        if (isInDatabase != other.isInDatabase) return false
        if (isMalicious != other.isMalicious) return false

        return true
    }

    override fun hashCode(): Int {
        var result = appInfo.hashCode()
        result = 31 * result + appName.hashCode()
        result = 31 * result + (appPackageName?.hashCode() ?: 0)
        result = 31 * result + (version?.hashCode() ?: 0)
        result = 31 * result + mlModelInput.contentHashCode()
        result = 31 * result + isInDatabase.hashCode()
        result = 31 * result + isMalicious.hashCode()
        return result
    }
}