package com.example.android.appsecurityv2.monitoring

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log

class StartReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent != null) {
            if (intent.action == Intent.ACTION_BOOT_COMPLETED && getServiceState(context) == ServiceState.STARTED) {
                Intent(context, EndlessService::class.java).also {
                    it.action = Actions.START.name
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        Log.d("ForegroundService", "Starting the service in >=26 Mode from a BroadcastReceiver")
                        context.startForegroundService(it)
                        return
                    }
                    Log.d("ForegroundService", "Starting the service in <26 Mode from a BroadcastReceiver")
                    context.startService(it)
                }
            }
        }
    }
}