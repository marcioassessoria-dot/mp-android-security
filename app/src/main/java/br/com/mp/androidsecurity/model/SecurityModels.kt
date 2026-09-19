package br.com.mp.androidsecurity.model
enum class RiskLevel(val label:String){LOW("Baixo"),ATTENTION("Atenção"),SUSPICIOUS("Suspeito"),HIGH("Alto risco")}
data class PermissionFinding(val permission:String,val label:String,val granted:Boolean,val riskPoints:Int)
data class InstalledAppInfo(val packageName:String,val appName:String,val versionName:String?,val isSystemApp:Boolean,val requestedPermissions:List<PermissionFinding>,val accessibilityEnabled:Boolean,val deviceAdminActive:Boolean,val riskScore:Int,val riskLevel:RiskLevel)
data class AccessibilityFinding(val packageName:String,val serviceName:String,val label:String)
data class DeviceAdminFinding(val packageName:String,val receiverName:String,val label:String)
data class ScanResult(val apps:List<InstalledAppInfo>,val accessibility:List<AccessibilityFinding>,val deviceAdmins:List<DeviceAdminFinding>,val durationMs:Long){val highRiskCount get()=apps.count{it.riskLevel==RiskLevel.HIGH};val suspiciousCount get()=apps.count{it.riskLevel==RiskLevel.SUSPICIOUS};val attentionCount get()=apps.count{it.riskLevel==RiskLevel.ATTENTION}}