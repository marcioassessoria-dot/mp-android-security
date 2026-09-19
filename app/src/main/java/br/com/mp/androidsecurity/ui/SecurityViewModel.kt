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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

data class SecurityUiState(val scanning:Boolean=false,val result:ScanResult?=null,val error:String?=null)

class SecurityViewModel(a:Application):AndroidViewModel(a){
 private val threatRepo=ThreatIntelRepository(a)
 private val _threatIntel=MutableStateFlow(threatRepo.cachedState())
 val threatIntel:StateFlow<ThreatIntelState> = _threatIntel
 private val _state=MutableStateFlow(SecurityUiState());val state:StateFlow<SecurityUiState> = _state

 init{ThreatIntelWorker.schedule(a);syncThreatIntel()}

 fun syncThreatIntel(){if(_threatIntel.value.syncing)return;_threatIntel.value=_threatIntel.value.copy(syncing=true,error=null);viewModelScope.launch(Dispatchers.IO){val r=threatRepo.sync();_threatIntel.value=r.copy(syncing=false)}}

 fun scan(){if(_state.value.scanning)return;_state.value=_state.value.copy(scanning=true,error=null);viewModelScope.launch(Dispatchers.Default){try{_state.value=SecurityUiState(result=LocalSecurityScanner(getApplication<Application>()).scan())}catch(t:Throwable){_state.value=SecurityUiState(error=t.message)}}}
 fun open(intent:Intent){getApplication<Application>().startActivity(intent)}
 private fun intent(action:String,uri:Uri?=null)=Intent(action).apply{if(uri!=null)data=uri;addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)}
 fun appDetails(p:String)=intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,Uri.parse("package:$p"))
 fun uninstall(p:String)=intent(Intent.ACTION_DELETE,Uri.parse("package:$p"))
 fun notificationSettings(p:String)=intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).apply{putExtra(Settings.EXTRA_APP_PACKAGE,p);addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)}
 fun accessibilitySettings()=intent(Settings.ACTION_ACCESSIBILITY_SETTINGS);fun deviceAdminSettings()=intent("android.settings.SECURITY_SETTINGS");fun emergencySettings()=intent(Settings.ACTION_SETTINGS);fun safeModeSettings()=intent(Settings.ACTION_SETTINGS);fun privateDnsSettings()=intent(Settings.ACTION_WIRELESS_SETTINGS)
 fun vpnPrepare():Intent?=VpnService.prepare(getApplication<Application>())
 fun startAdBlock(){val i=Intent(getApplication<Application>(),AdBlockVpnService::class.java);if(Build.VERSION.SDK_INT>=26)getApplication<Application>().startForegroundService(i)else getApplication<Application>().startService(i)}
 fun stopAdBlock(){getApplication<Application>().stopService(Intent(getApplication<Application>(),AdBlockVpnService::class.java))}
 fun clearNetworkEvents(){NetworkBlockStore.clear()};fun blockDomain(d:String){NetworkBlockStore.blockDomain(d)};fun allowDomain(d:String){NetworkBlockStore.allowDomain(d)}
 fun shareReport(result:ScanResult,events:List<br.com.mp.androidsecurity.model.NetworkBlockEvent>){val uri=ReportGenerator.createPdf(getApplication(),result,events);open(Intent.createChooser(Intent(Intent.ACTION_SEND).apply{type="application/pdf";putExtra(Intent.EXTRA_STREAM,uri);addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)},"Compartilhar relatório"))}
}