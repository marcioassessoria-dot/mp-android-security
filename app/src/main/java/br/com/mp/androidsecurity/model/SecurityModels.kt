package br.com.mp.androidsecurity.model

enum class RiskLevel(val label: String) { LOW("Baixo"), ATTENTION("Atenção"), SUSPICIOUS("Suspeito"), HIGH("Alto risco") }
enum class AdwareLevel(val label: String) { NONE("Sem indícios"), POSSIBLE("Possível adware"), HIGH("Alto indício de adware") }
enum class AppOrigin(val label:String){ ANDROID_CORE("Nativo do Android"), SYSTEM_PREINSTALLED("Pré-instalado pelo fabricante"), USER_INSTALLED("Instalado pelo usuário") }
data class PermissionFinding(val permission: String,val label: String,val granted: Boolean,val riskPoints: Int)
data class AdwareIndicator(val title:String,val detail:String,val points:Int)
data class InstalledAppInfo(val packageName:String,val appName:String,val versionName:String?,val versionCode:Long,val targetSdk:Int,val isSystemApp:Boolean,val origin:AppOrigin,val enabled:Boolean,val installer:String?,val firstInstallTime:Long,val lastUpdateTime:Long,val requestedPermissions:List<PermissionFinding>,val accessibilityEnabled:Boolean,val deviceAdminActive:Boolean,val riskReasons:List<String>,val riskScore:Int,val riskLevel:RiskLevel,val adwareIndicators:List<AdwareIndicator>,val adwareScore:Int,val adwareLevel:AdwareLevel)
data class AccessibilityFinding(val packageName:String,val serviceName:String,val label:String)
data class DeviceAdminFinding(val packageName:String,val receiverName:String,val label:String)
enum class MonitoringLevel(val label:String){CLEAR("Nenhum indicador relevante"),ATTENTION("Revisar configurações"),HIGH("Múltiplos indicadores")}
data class MonitoringFinding(val title:String,val detail:String,val severity:Int)
data class MonitoringStatus(val level:MonitoringLevel,val findings:List<MonitoringFinding>)
data class ScanResult(val apps:List<InstalledAppInfo>,val browsers:List<InstalledAppInfo>,val accessibility:List<AccessibilityFinding>,val deviceAdmins:List<DeviceAdminFinding>,val monitoring:MonitoringStatus,val durationMs:Long){val highRiskCount get()=apps.count{it.riskScore>=80};val suspiciousCount get()=apps.count{it.riskLevel==RiskLevel.SUSPICIOUS};val attentionCount get()=apps.count{it.riskLevel==RiskLevel.ATTENTION};val lowRiskCount get()=apps.count{it.riskLevel==RiskLevel.LOW};val possibleAdwareCount get()=apps.count{it.adwareLevel!=AdwareLevel.NONE};val highAdwareCount get()=apps.count{it.adwareLevel==AdwareLevel.HIGH}}