package br.com.mp.androidsecurity.scanner
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.provider.Settings
import br.com.mp.androidsecurity.model.*
import kotlin.system.measureTimeMillis
class LocalSecurityScanner(private val c:Context){
 private val apps=InstalledAppsScanner(c); private val browser=BrowserScanner(c); private val acc=AccessibilityScanner(c); private val admins=DeviceAdminScanner(c)
 fun scan():ScanResult{
  lateinit var a:List<AccessibilityFinding>; lateinit var d:List<DeviceAdminFinding>; lateinit var p:List<InstalledAppInfo>; lateinit var b:List<InstalledAppInfo>; lateinit var mon:MonitoringStatus
  val ms=measureTimeMillis{a=acc.scan();d=admins.scan();p=apps.scan(a.map{it.packageName}.toSet(),d.map{it.packageName}.toSet());val bp=browser.scan();b=p.filter{it.packageName in bp};mon=monitoring(a,d,p)}
  return ScanResult(p,b,a,d,mon,ms)
 }
 private fun monitoring(a:List<AccessibilityFinding>,d:List<DeviceAdminFinding>,apps:List<InstalledAppInfo>):MonitoringStatus{
  val f=mutableListOf<MonitoringFinding>()
  if(a.isNotEmpty()) f+=MonitoringFinding("Acessibilidade ativa","Existem ${a.size} serviço(s) de acessibilidade ativos. Isso pode permitir leitura da tela e automação; revise serviços que você não reconhece.",2)
  if(d.isNotEmpty()) f+=MonitoringFinding("Administrador do dispositivo","Existem ${d.size} administrador(es) ativo(s). Revise qualquer administrador que você não tenha autorizado.",2)
  val listeners=Settings.Secure.getString(c.contentResolver,"enabled_notification_listeners").orEmpty()
  if(listeners.isNotBlank()) f+=MonitoringFinding("Acesso a notificações","Há serviço(s) com acesso às notificações. Esse acesso pode expor o conteúdo das notificações ao aplicativo.",1)
  val dpm=c.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
  if(dpm.isDeviceOwnerApp(c.packageName)||dpm.isProfileOwnerApp(c.packageName)) f+=MonitoringFinding("Gerenciamento deste aparelho","O próprio MP Android Security está registrado como proprietário/perfil, o que não indica monitoramento externo.",0)
  val cm=c.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
  val vpn=cm.allNetworks.any{n->cm.getNetworkCapabilities(n)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)==true}
  if(vpn) f+=MonitoringFinding("VPN ativa","Há uma conexão VPN ativa. VPN pode ser legítima; verifique o aplicativo ou serviço responsável se você não a reconhece.",1)
  val elevated=apps.count{it.accessibilityEnabled||it.deviceAdminActive||it.adwareLevel==AdwareLevel.HIGH}
  if(elevated>=2) f+=MonitoringFinding("Múltiplos indicadores","Foram encontrados múltiplos sinais que justificam uma revisão manual dos aplicativos e configurações.",2)
  val score=f.sumOf{it.severity}
  return MonitoringStatus(if(score>=4)MonitoringLevel.HIGH else if(score>0)MonitoringLevel.ATTENTION else MonitoringLevel.CLEAR,f)
 }
}