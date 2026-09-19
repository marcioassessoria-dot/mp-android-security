package br.com.mp.androidsecurity.ui

import android.text.format.DateFormat
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import br.com.mp.androidsecurity.model.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecurityApp(vm:SecurityViewModel){
 val state by vm.state.collectAsState()
 Scaffold(topBar={TopAppBar(title={Text("MP Android Security")})}){pad->
  LazyColumn(Modifier.fillMaxSize().padding(pad).padding(16.dp),verticalArrangement=Arrangement.spacedBy(10.dp)){
   item{Text("Análise completa de aplicativos",style=MaterialTheme.typography.headlineSmall);Text("Permissões, acessibilidade, administrador, instalação e nível de risco.") }
   item{Button(onClick=vm::scan,enabled=!state.scanning,modifier=Modifier.fillMaxWidth()){Text(if(state.scanning)"ANALISANDO..." else "ANALISAR APLICATIVOS")}}
   state.error?.let{item{Text("Erro: $it",color=MaterialTheme.colorScheme.error)}}
   state.result?.let{result->
    item{
     Card{Column(Modifier.padding(16.dp),verticalArrangement=Arrangement.spacedBy(5.dp)){
      Text("Resumo da análise",style=MaterialTheme.typography.titleLarge)
      Text("Aplicativos analisados: ${result.apps.size}")
      Text("Alto risco: ${result.highRiskCount}  •  Suspeitos: ${result.suspiciousCount}")
      Text("Atenção: ${result.attentionCount}  •  Baixo: ${result.lowRiskCount}")
      Text("Acessibilidade ativa: ${result.accessibility.size}  •  Administradores: ${result.deviceAdmins.size}")
      Text("Tempo: ${result.durationMs} ms")
     }}
    }
    items(result.apps,key={it.packageName}){app->AppCard(app)}
   }
  }
 }
}

@Composable
private fun AppCard(app:InstalledAppInfo){
 var expanded by remember(app.packageName){mutableStateOf(false)}
 Card{Column(Modifier.padding(14.dp),verticalArrangement=Arrangement.spacedBy(5.dp)){
  Text(app.appName,style=MaterialTheme.typography.titleMedium)
  Text("Risco ${app.riskScore}/100 • ${app.riskLevel.label}")
  Text(app.packageName,style=MaterialTheme.typography.bodySmall)
  Row(horizontalArrangement=Arrangement.spacedBy(8.dp)){Text(if(app.isSystemApp)"Sistema" else "Instalado pelo usuário");Text(if(app.enabled)"Ativo" else "Desativado")}
  if(app.riskReasons.isNotEmpty()){Text("Indicadores:");app.riskReasons.take(if(expanded)10 else 3).forEach{Text("• $it",style=MaterialTheme.typography.bodySmall)}}
  TextButton(onClick={expanded=!expanded}){Text(if(expanded)"OCULTAR DETALHES" else "VER DETALHES")}
  if(expanded){
   HorizontalDivider()
   Text("Informações",style=MaterialTheme.typography.titleSmall)
   Text("Versão: ${app.versionName ?: "desconhecida"} (${app.versionCode})")
   Text("Target SDK: ${app.targetSdk}")
   Text("Instalado em: ${DateFormat.format("dd/MM/yyyy HH:mm",app.firstInstallTime)}")
   Text("Atualizado em: ${DateFormat.format("dd/MM/yyyy HH:mm",app.lastUpdateTime)}")
   Text("Instalador: ${app.installer ?: "desconhecido"}")
   if(app.accessibilityEnabled)Text("⚠ Acessibilidade ativa")
   if(app.deviceAdminActive)Text("⚠ Administrador do dispositivo ativo")
   Text("Permissões sensíveis",style=MaterialTheme.typography.titleSmall)
   if(app.requestedPermissions.isEmpty())Text("Nenhuma das permissões monitoradas foi declarada.")
   app.requestedPermissions.forEach{p->Text("${if(p.granted)"✓" else "○"} ${p.label} — ${if(p.granted)"concedida" else "não concedida"}")}
  }
 }}
}