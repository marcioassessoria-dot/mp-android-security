package br.com.mp.androidsecurity.model

enum class RiskLevel(val label: String) { LOW("Baixo"), ATTENTION("Atenção"), SUSPICIOUS("Suspeito"), HIGH("Alto risco") }
enum class AdwareLevel(val label: String) { NONE("Sem indícios"), POSSIBLE("Possível adware"), HIGH("Alto indício de adware") }
data class PermissionFinding(val permission: String,val label: String,val granted: Boolean,val riskPoints: Int)
data class AdwareIndicator(val title:String,val detail:String,val points:Int)
data class InstalledAppInfo(val packageName:String,val appName:String,val versionName:String?,val versionCode:Long,val targetSdk:Int,val isSystemApp:Boolean,val enabled:Boolean,val installer:String?,val firstInstallTime:Long,val lastUpdateTime:Long,val requestedPermissions:List<PermissionFinding>,val accessibilityEnabled:Boolean,val deviceAdminActive:Boolean,val riskReasons:List<String>,val riskScore:Int,val riskLevel:RiskLevel,val adwareIndicators:List<AdwareIndicator>,val adwareScore:Int,val adwareLevel:AdwareLevel)
data class AccessibilityFinding(val packageName:String,val serviceName:String,val label:String)
data class DeviceAdminFinding(val packageName:String,val receiverName:String,val label:String)
data class ScanResult(val apps:List<InstalledAppInfo>,val accessibility:List<AccessibilityFinding>,val deviceAdmins:List<DeviceAdminFinding>,val durationMs:Long){val highRiskCount get()=apps.count{it.riskLevel==RiskLevel.HIGH};val suspiciousCount get()=apps.count{it.riskLevel==RiskLevel.SUSPICIOUS};val attentionCount get()=apps.count{it.riskLevel==RiskLevel.ATTENTION};val lowRiskCount get()=apps.count{it.riskLevel==RiskLevel.LOW};val possibleAdwareCount get()=apps.count{it.adwareLevel!=AdwareLevel.NONE};val highAdwareCount get()=apps.count{it.adwareLevel==AdwareLevel.HIGH}}