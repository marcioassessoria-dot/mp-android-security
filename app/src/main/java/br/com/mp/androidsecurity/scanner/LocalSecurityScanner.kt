package br.com.mp.androidsecurity.scanner
import android.app.ActivityManager
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.BatteryManager
import android.os.Build
import android.os.Environment
import android.os.StatFs
import android.provider.Settings
import br.com.mp.androidsecurity.model.*
import br.com.mp.androidsecurity.threat.ThreatIntelRepository
import kotlin.system.measureTimeMillis
class LocalSecurityScanner(private val c:Context){
 private val apps=InstalledAppsScanner(c); private val threatRepo=ThreatIntelRepository(c); private val browser=BrowserScanner(c); private val acc=AccessibilityScanner(c); private val admins=DeviceAdminScanner(c)
 fun scan():ScanResult{ lateinit var a:List<AccessibilityFinding>;lateinit var d:List<DeviceAdminFinding>;lateinit var p:List<InstalledAppInfo>;lateinit var b:List<InstalledAppInfo>;lateinit var m:MonitoringStatus;lateinit var dns:PrivateDnsStatus;lateinit var diag:DeviceDiagnostics
  val ms=measureTimeMillis{a=acc.scan();d=admins.scan();p=apps.scan(a.map{it.packageName}.toSet(),d.map{it.packageName}.toSet(),threatRepo.cachedState().threats);val bp=browser.scan();b=p.filter{it.packageName in bp};m=monitoring(a,d,p);dns=privateDns();diag=diagnostics()}
  return ScanResult(p,b,a,d,m,dns,diag,ms)
 }
 private fun diagnostics():DeviceDiagnostics{
  val cm=c.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager; val vpn=cm.allNetworks.any{cm.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)==true}
  val am=c.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager;val mem=ActivityManager.MemoryInfo();am.getMemoryInfo(mem);val st=StatFs(Environment.getDataDirectory().path)
  val bm=c.getSystemService(Context.BATTERY_SERVICE) as BatteryManager;val battery=runCatching{bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)}.getOrNull()?.takeIf{it in 0..100};val charging=runCatching{bm.isCharging}.getOrNull()
  val adb=Settings.Global.getInt(c.contentResolver,Settings.Global.ADB_ENABLED,0)==1;val dev=Settings.Global.getInt(c.contentResolver,Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,0)==1
  val encrypted=if(Build.VERSION.SDK_INT>=23)Environment.isExternalStorageEmulated()||Build.VERSION.SDK_INT>=24 else false
  return DeviceDiagnostics(Build.MANUFACTURER,Build.MODEL,Build.VERSION.RELEASE,Build.VERSION.SDK_INT,if(Build.VERSION.SDK_INT>=23)Build.VERSION.SECURITY_PATCH else null,mem.totalMem/1048576,st.availableBytes/1048576,st.totalBytes/1048576,battery,charging,dev,adb,vpn,encrypted)
 }
 private fun privateDns():PrivateDnsStatus{
  if(Build.VERSION.SDK_INT<Build.VERSION_CODES.P)return PrivateDnsStatus(PrivateDnsState.UNSUPPORTED,null,false,"O Android deste aparelho não oferece a configuração de DNS privado.")
  val mode=Settings.Global.getString(c.contentResolver,"private_dns_mode").orEmpty().lowercase();val provider=Settings.Global.getString(c.contentResolver,"private_dns_specifier")?.trim()?.takeIf{it.isNotBlank()};val n=provider?.lowercase()?.removeSuffix(".")
  val ad=n=="dns.adguard.com"||n=="dns.adguard-dns.com"||n=="family.adguard-dns.com"||n=="unfiltered.adguard-dns.com"
  return when(mode){"off"->PrivateDnsStatus(PrivateDnsState.OFF,provider,false,"DNS privado está desativado.");"opportunistic"->PrivateDnsStatus(PrivateDnsState.AUTOMATIC,provider,false,"DNS privado está em modo automático.");"hostname"->PrivateDnsStatus(PrivateDnsState.PROVIDER,provider,ad,if(ad)"AdGuard DNS identificado." else "Provedor DNS personalizado identificado.");else->PrivateDnsStatus(PrivateDnsState.UNKNOWN,provider,ad,"Modo de DNS não identificado com segurança.")}
 }
 private fun monitoring(a:List<AccessibilityFinding>,d:List<DeviceAdminFinding>,apps:List<InstalledAppInfo>):MonitoringStatus{
  val f=mutableListOf<MonitoringFinding>();if(a.isNotEmpty())f+=MonitoringFinding("Acessibilidade ativa","${a.size} serviço(s) ativo(s). Revise serviços que você não reconhece.",2);if(d.isNotEmpty())f+=MonitoringFinding("Administrador do dispositivo","${d.size} administrador(es) ativo(s).",2)
  if(Settings.Secure.getString(c.contentResolver,"enabled_notification_listeners").orEmpty().isNotBlank())f+=MonitoringFinding("Acesso a notificações","Há serviço(s) com acesso às notificações.",1)
  val cm=c.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager;val vpn=cm.allNetworks.any{cm.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)==true};if(vpn)f+=MonitoringFinding("VPN ativa","Há uma VPN ativa; confirme o serviço responsável.",1)
  val elevated=apps.count{it.accessibilityEnabled||it.deviceAdminActive||it.adwareLevel==AdwareLevel.HIGH};if(elevated>=2)f+=MonitoringFinding("Múltiplos indicadores","Foram encontrados múltiplos sinais que justificam revisão manual.",2)
  val s=f.sumOf{it.severity};return MonitoringStatus(if(s>=4)MonitoringLevel.HIGH else if(s>0)MonitoringLevel.ATTENTION else MonitoringLevel.CLEAR,f)
 }
}