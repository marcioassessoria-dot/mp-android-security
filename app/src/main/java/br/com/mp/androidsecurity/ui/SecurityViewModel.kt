package br.com.mp.androidsecurity.ui
import android.app.Application
import android.content.Intent
import android.net.Uri
import android.provider.Settings
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
 fun scan(){if(_state.value.scanning)return;_state.value=_state.value.copy(scanning=true);viewModelScope.launch(Dispatchers.Default){try{_state.value=SecurityUiState(result=LocalSecurityScanner(getApplication()).scan())}catch(t:Throwable){_state.value=SecurityUiState(error=t.message)}}}}
 fun intent(action:String,uri:Uri?=null):Intent=Intent(action).apply{if(uri!=null)data=uri;addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)}
 fun appDetails(packageName:String)=intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,Uri.parse("package:$packageName"))
 fun uninstall(packageName:String)=intent(Intent.ACTION_DELETE,Uri.parse("package:$packageName"))
 fun permissions(packageName:String)=intent("android.intent.action.MANAGE_APP_ALL_FILES_ACCESS_PERMISSION",Uri.parse("package:$packageName"))
 fun notificationSettings(packageName:String)=intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).apply{putExtra(Settings.EXTRA_APP_PACKAGE,packageName)}
 fun accessibilitySettings()=intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
 fun deviceAdminSettings()=intent("android.settings.SECURITY_SETTINGS")
 fun emergencySettings()=intent(Settings.ACTION_SETTINGS)
}
