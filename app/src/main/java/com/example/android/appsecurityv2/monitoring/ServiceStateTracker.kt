package com.example.android.appsecurityv2.monitoring

import android.content.Context
import android.content.SharedPreferences

enum class ServiceState {
    STARTED,
    STOPPED,
}

private const val name = "SERVICE_NAME"
private const val key = "SERVICE_SECRET_KEY"

private fun getPreferences(context: Context): SharedPreferences {
    return context.getSharedPreferences(name, 0)
}

fun setServiceState(context: Context, state: ServiceState) {
    val sharedPref = getPreferences(context)
    sharedPref.edit().let {
        it.putString(key, state.name)
        it.apply()
    }
}

fun getServiceState(context: Context): ServiceState? {
    val sharedPrefs = getPreferences(context)
    val value = sharedPrefs.getString(key, ServiceState.STOPPED.name)
    return value?.let { ServiceState.valueOf(it) }
}
