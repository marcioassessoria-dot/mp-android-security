package br.com.mp.androidsecurity

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Phone
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import br.com.mp.androidsecurity.threat.ThreatIntelWorker
import br.com.mp.androidsecurity.ui.CallScreeningActivity
import br.com.mp.androidsecurity.ui.SecurityApp
import br.com.mp.androidsecurity.ui.SecurityViewModel

class MainActivity : ComponentActivity() {
    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        ThreatIntelWorker.schedule(this)
        setContent { SecurityHome(viewModel<SecurityViewModel>()) }
    }

    @Composable
    private fun SecurityHome(vm: SecurityViewModel) {
        Box(Modifier.fillMaxSize()) {
            SecurityApp(vm)
            FloatingActionButton(
                onClick = { startActivity(Intent(this@MainActivity, CallScreeningActivity::class.java)) },
                modifier = Modifier.align(Alignment.BottomEnd).padding(18.dp)
            ) { Icon(Icons.Default.Phone, contentDescription = "Filtragem de chamadas") }
        }
    }
}
