package br.com.mp.androidsecurity
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.lifecycle.viewmodel.compose.viewModel
import br.com.mp.androidsecurity.ui.SecurityApp
import br.com.mp.androidsecurity.ui.SecurityViewModel
import br.com.mp.androidsecurity.threat.ThreatIntelWorker
class MainActivity:ComponentActivity(){override fun onCreate(b:Bundle?){super.onCreate(b);ThreatIntelWorker.schedule(this);setContent{SecurityApp(viewModel<SecurityViewModel>())}}}