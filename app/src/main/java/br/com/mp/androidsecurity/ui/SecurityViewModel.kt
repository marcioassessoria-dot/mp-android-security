package br.com.mp.androidsecurity.ui
import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import br.com.mp.androidsecurity.model.ScanResult
import br.com.mp.androidsecurity.scanner.LocalSecurityScanner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
data class SecurityUiState(val scanning:Boolean=false,val result:ScanResult?=null,val error:String?=null)
class SecurityViewModel(a:Application):AndroidViewModel(a){private val _state=MutableStateFlow(SecurityUiState());val state:StateFlow<SecurityUiState> = _state;fun scan(){if(_state.value.scanning)return;_state.value=_state.value.copy(scanning=true);viewModelScope.launch(Dispatchers.Default){try{_state.value=SecurityUiState(result=LocalSecurityScanner(getApplication()).scan())}catch(t:Throwable){_state.value=SecurityUiState(error=t.message)}}}}