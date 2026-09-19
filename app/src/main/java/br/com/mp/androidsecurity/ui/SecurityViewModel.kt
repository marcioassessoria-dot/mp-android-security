package br.com.mp.androidsecurity.ui
import android.app.Application
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.net.VpnService
import android.os.Build
import br.com.mp.androidsecurity.network.AdBlockVpnService
import br.com.mp.androidsecurity.network.NetworkBlockStore
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
 private val _state=MutableStateFlow(SecurityUiState())
 val state:StateFlow<SecurityUiState> = _state

 fun scan(){
  if(_state.value.scanning)return
  _state.value=_state.value.copy(scanning=true,error=null)
  viewModelScope.launch(Dispatchers.Default){
   try{_state.value=SecurityUiState(result=LocalSecurityScanner(getApplication<Application>()).scan())}
   catch(t:Throwable){_state.value=SecurityUiState(error=t.message)}
  }
 }

 fun open(intent:Intent){getApplication<Application>().startActivity(intent)}
 fun intent(action:String,uri:Uri?=null):Intent=Intent(action).apply{if(uri!=null)data=uri;addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)}
 fun appDetails(packageName:String)=intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,Uri.parse("package:$packageName"))
 fun uninstall(packageName:String)=intent(Intent.ACTION_DELETE,Uri.parse("package:$packageName"))
 fun permissions(packageName:String)=appDetails(packageName)
 fun notificationSettings(packageName:String)=intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).apply{putExtra(Settings.EXTRA_APP_PACKAGE,packageName)}
 fun accessibilitySettings()=intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
 fun deviceAdminSettings()=intent("android.settings.SECURITY_SETTINGS")
 fun emergencySettings()=intent(Settings.ACTION_SETTINGS)
 fun safeModeSettings()=intent(Settings.ACTION_SETTINGS)
 fun privateDnsSettings()=intent(Settings.ACTION_WIRELESS_SETTINGS)
 fun vpnPrepare():Intent?=VpnService.prepare(getApplication<Application>())
 fun startAdBlock(){val i=Intent(getApplication<Application>(),AdBlockVpnService::class.java);if(Build.VERSION.SDK_INT>=26)getApplication<Application>().startForegroundService(i) else getApplication<Application>().startService(i)}
 fun stopAdBlock(){getApplication<Application>().stopService(Intent(getApplication<Application>(),AdBlockVpnService::class.java))}
 fun clearNetworkEvents(){NetworkBlockStore.clear()}
}
