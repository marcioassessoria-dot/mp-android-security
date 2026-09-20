package br.com.mp.androidsecurity.model

data class RemovalAction(
    val packageName: String,
    val appName: String,
    val action: String,
    val timestamp: Long
)

data class RemovalSession(
    val startedAt: Long,
    val targetPackage: String,
    val targetAppName: String,
    val before: ScanResult,
    val actions: List<RemovalAction> = emptyList(),
    val after: ScanResult? = null
) {
    val completed: Boolean get() = after != null
}
