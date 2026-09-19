package br.com.mp.androidsecurity.threat

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

class ThreatIntelWorker(appContext: Context, workerParams: WorkerParameters) : CoroutineWorker(appContext, workerParams) {
    override suspend fun doWork(): Result = runCatching { ThreatIntelRepository(applicationContext).sync() }
        .fold(onSuccess = { Result.success() }, onFailure = { Result.retry() })

    companion object {
        private const val UNIQUE_NAME = "mp-threat-intel-periodic-sync"
        fun schedule(context: Context) {
            val request = PeriodicWorkRequestBuilder<ThreatIntelWorker>(12, TimeUnit.HOURS)
                .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(UNIQUE_NAME, ExistingPeriodicWorkPolicy.UPDATE, request)
        }
    }
}
