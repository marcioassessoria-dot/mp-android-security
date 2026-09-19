package br.com.mp.androidsecurity.scanner
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import br.com.mp.androidsecurity.model.*
class InstalledAppsScanner(private val c:Context){
 private val pm=c.packageManager
 fun scan(acc:Set<String>,admins:Set<String>):List<InstalledAppInfo>=pm.getInstalledPackages(PackageManager.GET_PERMISSIONS).mapNotNull{pkg->
  val ai=pkg.applicationInfo?:return@mapNotNull null
  val allRequested=pkg.requestedPermissions.orEmpty().toList()
  val requested=allRequested.filter(RiskEngine::isSensitive)
  val granted=requested.filter{pm.checkPermission(it,pkg.packageName)==PackageManager.PERMISSION_GRANTED}.toSet()
  val findings=requested.map{PermissionFinding(it,RiskEngine.label(it),it in granted,RiskEngine.points(it))}
  val accessibility=pkg.packageName in acc
  val admin=pkg.packageName in admins
  val score=RiskEngine.score(requested,granted,accessibility,admin)
  val installer=runCatching{if(Build.VERSION.SDK_INT>=30)pm.getInstallSourceInfo(pkg.packageName).installingPackageName else @Suppress("DEPRECATION") pm.getInstallerPackageName(pkg.packageName)}.getOrNull()
  val adIndicators=RiskEngine.adwareIndicators(allRequested,granted,accessibility,installer,pkg.firstInstallTime,(ai.flags and ApplicationInfo.FLAG_SYSTEM)!=0)
  val adScore=RiskEngine.adwareScore(adIndicators,granted,accessibility)
  val adLevel=RiskEngine.adwareLevel(adScore,adIndicators)
  val versionCode=if(Build.VERSION.SDK_INT>=28)pkg.longVersionCode else @Suppress("DEPRECATION") pkg.versionCode.toLong()
  InstalledAppInfo(pkg.packageName,ai.loadLabel(pm).toString(),pkg.versionName,versionCode,ai.targetSdkVersion,(ai.flags and ApplicationInfo.FLAG_SYSTEM)!=0,ai.enabled,installer,pkg.firstInstallTime,pkg.lastUpdateTime,findings,accessibility,admin,(RiskEngine.reasons(requested,granted,accessibility,admin)+when(adLevel){AdwareLevel.HIGH->listOf("Possível adware: combinação de múltiplos indicadores");AdwareLevel.POSSIBLE->listOf("Indícios de possível adware: investigar os indicadores");else->emptyList()}).distinct(),score,RiskEngine.level(score),adIndicators,adScore,adLevel)
 }.sortedByDescending{it.riskScore}
}