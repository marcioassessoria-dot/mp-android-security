package br.com.mp.androidsecurity.ui
import android.app.Application
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.net.VpnService
import android.os.Build
import br.com.mp.androidsecurity.network.AdBlockVpnService
import br.com.mp.androidsecurity.network.NetworkBlockStore
import br.com.mp.androidsecurity.report.ReportGenerator
import br.com.mp.androidsecurity.threat.ThreatIntelRepository
import br.com.mp.androidsecurity.threat.ThreatIntelState
import br.com.mp.androidsecurity.threat.ThreatIntelWorker
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import br.com.mp.androidsecurity.model.ScanResult
import br.com.mp.androidsecurity.scanner.LocalSecurityScanner
import br.com.mp.androidsecurity.scanner.MetaDefenderScanner
import br.com.mp.androidsecurity.scanner.OnlineScanResult
import br.com.mp.androidsecurity.scanner.PortalNexAiClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

data class SecurityUiState(val scanning:Boolean=false,val result:ScanResult?=null,val error:String?=null,val onlineScanningPackage:String?=null,val onlineResults:Map<String,OnlineScanResult> = emptyMap(),val onlineError:String?=null,val metaDefenderApiKey:String="",val removalSession:br.com.mp.androidsecurity.model.RemovalSession?=null,val removalRunning:Boolean=false,val removalMessage:String?=null,val aiRunning:Boolean=false,val aiAnalysis:String?=null,val aiError:String?=null)

class SecurityViewModel(a:Application):AndroidViewModel(a){
 private val threatRepo=ThreatIntelRepository(a)
 private val _threatIntel=MutableStateFlow(threatRepo.cachedState())
 val threatIntel:StateFlow<ThreatIntelState> = _threatIntel
 private val _state=MutableStateFlow(SecurityUiState());val state:StateFlow<SecurityUiState> = _state
 private val onlineScanner=MetaDefenderScanner(a)
 private val portalNexAi=PortalNexAiClient(a)

 init{ThreatIntelWorker.schedule(a);syncThreatIntel()}

 fun syncThreatIntel(){if(_threatIntel.value.syncing)return;_threatIntel.value=_threatIntel.value.copy(syncing=true,error=null);viewModelScope.launch(Dispatchers.IO){val r=threatRepo.sync();_threatIntel.value=r.copy(syncing=false)}}

 fun setMetaDefenderApiKey(value:String){_state.value=_state.value.copy(metaDefenderApiKey=value,onlineError=null)}
 fun scanOnline(app:br.com.mp.androidsecurity.model.InstalledAppInfo){
  val key=BuildConfig.METADEFENDER_API_KEY
  if(key.isBlank()){_state.value=_state.value.copy(onlineError="Informe a API key do MetaDefender Cloud.");return}
  if(_state.value.onlineScanningPackage!=null)return
  _state.value=_state.value.copy(onlineScanningPackage=app.packageName,onlineError=null)
  viewModelScope.launch(Dispatchers.IO){try{val result=onlineScanner.scanInstalledApp(app,key);_state.value=_state.value.copy(onlineScanningPackage=null,onlineResults=_state.value.onlineResults+(app.packageName to result))}catch(t:Throwable){_state.value=_state.value.copy(onlineScanningPackage=null,onlineError=t.message?: "Falha no scanner online")}}
 }
 fun scanOnlineAll(){
  val result=_state.value.result ?: run { scan(); return }
  val key=BuildConfig.METADEFENDER_API_KEY
  if(key.isBlank()){_state.value=_state.value.copy(onlineError="Scanner online não configurado no build.");return}
  if(_state.value.onlineScanningPackage!=null)return
  viewModelScope.launch(Dispatchers.IO){
   for(app in result.apps.filter{!it.isSystemApp}){
    _state.value=_state.value.copy(onlineScanningPackage=app.packageName,onlineError=null)
    try{
     val online=onlineScanner.scanInstalledApp(app,key)
     _state.value=_state.value.copy(onlineResults=_state.value.onlineResults+(app.packageName to online))
    }catch(t:Throwable){
     _state.value=_state.value.copy(onlineError=t.message?: "Falha na análise online")
    }
   }
   _state.value=_state.value.copy(onlineScanningPackage=null)
  }
 }
 fun analyzeWithPortalNexAi(){
  val result=_state.value.result ?: run { scan(); return }
  if(_state.value.aiRunning)return
  _state.value=_state.value.copy(aiRunning=true,aiError=null)
  viewModelScope.launch(Dispatchers.IO){
   try{
    val analysis=portalNexAi.analyze(result)
    _state.value=_state.value.copy(aiRunning=false,aiAnalysis=analysis)
   }catch(t:Throwable){
    _state.value=_state.value.copy(aiRunning=false,aiError=t.message?:"Falha na análise por IA")
   }
  }
 }
 fun startRemoval(app:br.com.mp.androidsecurity.model.InstalledAppInfo){
  val before=_state.value.result ?: return
  _state.value=_state.value.copy(removalSession=br.com.mp.androidsecurity.model.RemovalSession(System.currentTimeMillis(),app.packageName,app.appName,before),removalMessage="Sessão de remoção iniciada. Revise o aplicativo e confirme a desinstalação pelo Android.")
 }
 fun markRemovalAction(action:String){
  val s=_state.value.removalSession ?: return
  _state.value=_state.value.copy(removalSession=s.copy(actions=s.actions+br.com.mp.androidsecurity.model.RemovalAction(s.targetPackage,s.targetAppName,action,System.currentTimeMillis())))
 }
 fun scanAfterRemoval(){
  val s=_state.value.removalSession ?: return
  if(_state.value.removalRunning)return
  _state.value=_state.value.copy(removalRunning=true,removalMessage="Executando nova análise para comparar antes e depois...")
  viewModelScope.launch(Dispatchers.Default){
   try{
    val after=LocalSecurityScanner(getApplication<Application>()).scan()
    val exists=after.apps.any{it.packageName==s.targetPackage}
    val msg=if(exists)"O aplicativo ainda está instalado. Verifique a remoção e repita a análise." else "O aplicativo alvo não foi encontrado na nova análise."
    _state.value=_state.value.copy(removalRunning=false,removalSession=s.copy(after=after),removalMessage=msg)
   }catch(t:Throwable){_state.value=_state.value.copy(removalRunning=false,removalMessage=t.message?:"Falha na análise pós-remoção")}
  }
 }
 fun clearRemovalSession(){_state.value=_state.value.copy(removalSession=null,removalMessage=null)}
 fun scan(){if(_state.value.scanning)return;_state.value=_state.value.copy(scanning=true,error=null);viewModelScope.launch(Dispatchers.Default){try{_state.value=SecurityUiState(result=LocalSecurityScanner(getApplication<Application>()).scan())}catch(t:Throwable){_state.value=SecurityUiState(error=t.message)}}}
 fun open(intent:Intent){getApplication<Application>().startActivity(intent)}
 private fun intent(action:String,uri:Uri?=null)=Intent(action).apply{if(uri!=null)data=uri;addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)}
 fun appDetails(p:String)=intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,Uri.parse("package:$p"))
 fun uninstall(p:String)=intent(Intent.ACTION_DELETE,Uri.parse("package:$p"))
 fun notificationSettings(p:String)=intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).apply{putExtra(Settings.EXTRA_APP_PACKAGE,p);addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)}
 fun accessibilitySettings()=intent(Settings.ACTION_ACCESSIBILITY_SETTINGS);fun deviceAdminSettings()=intent("android.settings.SECURITY_SETTINGS");fun emergencySettings()=intent(Settings.ACTION_SETTINGS);fun safeModeSettings()=intent(Settings.ACTION_SETTINGS);fun privateDnsSettings()=if(Build.VERSION.SDK_INT>=Build.VERSION_CODES.P) intent(Settings.ACTION_PRIVATE_DNS_SETTINGS) else intent(Settings.ACTION_WIRELESS_SETTINGS)
 fun adGuardDnsHost()="dns.adguard.com"
 fun adGuardDnsConfigured()=false
 fun vpnPrepare():Intent?=VpnService.prepare(getApplication<Application>())
 fun startAdBlock(){val i=Intent(getApplication<Application>(),AdBlockVpnService::class.java);if(Build.VERSION.SDK_INT>=26)getApplication<Application>().startForegroundService(i)else getApplication<Application>().startService(i)}
 fun stopAdBlock(){getApplication<Application>().stopService(Intent(getApplication<Application>(),AdBlockVpnService::class.java))}
 fun clearNetworkEvents(){NetworkBlockStore.clear()};fun blockDomain(d:String){NetworkBlockStore.blockDomain(d)};fun allowDomain(d:String){NetworkBlockStore.allowDomain(d)}
 fun shareReport(result:ScanResult,events:List<br.com.mp.androidsecurity.model.NetworkBlockEvent>){val uri=ReportGenerator.createPdf(getApplication(),result,events);open(Intent.createChooser(Intent(Intent.ACTION_SEND).apply{type="application/pdf";putExtra(Intent.EXTRA_STREAM,uri);addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)},"Compartilhar relatório"))}
}