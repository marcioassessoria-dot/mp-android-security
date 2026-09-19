package br.com.mp.androidsecurity.scanner
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import br.com.mp.androidsecurity.model.*
class InstalledAppsScanner(private val c:Context){
 private val pm=c.packageManager
 fun scan(acc:Set<String>,admins:Set<String>): List<InstalledAppInfo> =pm.getInstalledPackages(PackageManager.GET_PERMISSIONS).mapNotNull{pkg->
  val ai=pkg.applicationInfo?:return@mapNotNull null
  val allRequested=pkg.requestedPermissions.orEmpty().toList()
  val requested=allRequested.filter(RiskEngine::isSensitive)
  val granted=requested.filter{pm.checkPermission(it,pkg.packageName)==PackageManager.PERMISSION_GRANTED}.toSet()
  val findings=requested.map{PermissionFinding(it,RiskEngine.label(it),it in granted,RiskEngine.points(it))}
  val accessibility=pkg.packageName in acc
  val admin=pkg.packageName in admins
  val isSystem=(ai.flags and ApplicationInfo.FLAG_SYSTEM)!=0
  val origin=when {
   !isSystem -> AppOrigin.USER_INSTALLED
   pkg.packageName=="android" || pkg.packageName.startsWith("com.android.") -> AppOrigin.ANDROID_CORE
   else -> AppOrigin.SYSTEM_PREINSTALLED
  }
  val score=if(isSystem) (if(accessibility) 10 else 0)+(if(admin) 10 else 0) else RiskEngine.score(requested,granted,accessibility,admin)
  val installer=runCatching{if(Build.VERSION.SDK_INT>=30)pm.getInstallSourceInfo(pkg.packageName).installingPackageName else @Suppress("DEPRECATION") pm.getInstallerPackageName(pkg.packageName)}.getOrNull()
  val adIndicators=if(isSystem) emptyList() else RiskEngine.adwareIndicators(allRequested,granted,accessibility,installer,pkg.firstInstallTime,false)
  val adScore=if(isSystem) 0 else RiskEngine.adwareScore(adIndicators,granted,accessibility)
  val adLevel=RiskEngine.adwareLevel(adScore,adIndicators)
  val versionCode=if(Build.VERSION.SDK_INT>=28)pkg.longVersionCode else @Suppress("DEPRECATION") pkg.versionCode.toLong()
  val reasons=if(isSystem) buildList { if(accessibility) add("Serviço de acessibilidade ativo") ; if(admin) add("Administrador do dispositivo ativo") } else (RiskEngine.reasons(requested,granted,accessibility,admin)+when(adLevel){AdwareLevel.HIGH->listOf("Possível adware: combinação de múltiplos indicadores");AdwareLevel.POSSIBLE->listOf("Indícios de possível adware: investigar os indicadores");else->emptyList()}).distinct()
  InstalledAppInfo(pkg.packageName,ai.loadLabel(pm).toString(),pkg.versionName,versionCode,ai.targetSdkVersion,isSystem,origin,ai.enabled,installer,pkg.firstInstallTime,pkg.lastUpdateTime,findings,accessibility,admin,reasons,score,RiskEngine.level(score),adIndicators,adScore,adLevel)
 }.sortedByDescending{it.riskScore}
}