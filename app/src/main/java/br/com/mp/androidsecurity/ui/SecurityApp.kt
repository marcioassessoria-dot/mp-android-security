package br.com.mp.androidsecurity.ui
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import br.com.mp.androidsecurity.model.*
@Composable fun SecurityApp(vm:SecurityViewModel){
 val state by vm.state.collectAsState()
 Scaffold(topBar={TopAppBar(title={Text("MP Android Security")})}){pad->
  LazyColumn(Modifier.fillMaxSize().padding(pad).padding(16.dp),verticalArrangement=Arrangement.spacedBy(10.dp)){
   item{Text("Scanner local",style=MaterialTheme.typography.headlineSmall);Text("Apps, permissões, acessibilidade e administradores.")}
   item{Button(onClick=vm::scan,enabled=!state.scanning,modifier=Modifier.fillMaxWidth()){Text(if(state.scanning)"ANALISANDO..." else "INICIAR VARREDURA")}}
   state.error?.let{err->item{Text("Erro: " + err,color=MaterialTheme.colorScheme.error)}}
   state.result?.let{result->
    item{Card{Column(Modifier.padding(16.dp)){Text("Apps: " + result.apps.size);Text("Alto risco: " + result.highRiskCount);Text("Suspeitos: " + result.suspiciousCount);Text("Atenção: " + result.attentionCount);Text("Acessibilidade: " + result.accessibility.size);Text("Administradores: " + result.deviceAdmins.size)}}}
    items(result.apps.take(100),key={it.packageName}){app->
     item{Card{Column(Modifier.padding(12.dp)){Text(app.appName + " — " + app.riskLevel.label);Text(app.packageName);Text("Risco " + app.riskScore + "/100");if(app.accessibilityEnabled)Text("Acessibilidade ativa");if(app.deviceAdminActive)Text("Administrador ativo")}}}
    }
   }
  }
 }
}