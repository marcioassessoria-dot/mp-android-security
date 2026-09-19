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
   item{Button(onClick=vm::scan,enabled=!state.scanning,modifier=Modifier.fillMaxWidth()){Text(if(state.scanning)"ANALISANDO..." else "ANALISAR APLICATIVOS")}}\n   state.result?.let{r->item{Card{Row(Modifier.fillMaxWidth().padding(14.dp),horizontalArrangement=Arrangement.SpaceEvenly){Column{Text("Risco > 80",style=MaterialTheme.typography.titleSmall);Text(r.apps.count{it.riskScore>=80}.toString(),style=MaterialTheme.typography.headlineSmall)};Column{Text("Navegadores analisados",style=MaterialTheme.typography.titleSmall);Text(r.browsers.size.toString(),style=MaterialTheme.typography.headlineSmall)}}}}}
   item{AboutCard()}
   item{EmergencyCard(vm)}
   item{GuidedToolsCard(vm)}
   state.error?.let{item{Text("Erro: $it",color=MaterialTheme.colorScheme.error)}}
   state.result?.let{result->
    item{
     Card{Column(Modifier.padding(16.dp),verticalArrangement=Arrangement.spacedBy(5.dp)){
      Text("Resumo da análise",style=MaterialTheme.typography.titleLarge)
      Text("Aplicativos analisados: ${result.apps.size}")
      Text("Alto risco: ${result.highRiskCount}  •  Suspeitos: ${result.suspiciousCount}")
      Text("Atenção: ${result.attentionCount}  •  Baixo: ${result.lowRiskCount}")
      Text("Acessibilidade ativa: ${result.accessibility.size}  •  Administradores: ${result.deviceAdmins.size}")
      Text("Possível adware: ${result.possibleAdwareCount}  •  Alto indício: ${result.highAdwareCount}")
      Text("Monitoramento: ${result.monitoring.level.label}")
      Text("Tempo: ${result.durationMs} ms")
     }}
    }
    val highRisk=result.apps.filter{it.riskScore>=80}
    item{HighRiskHeader(highRisk.size)}
    items(highRisk,key={it.packageName}){app->AppCard(vm,app)}
    item{BrowserCard(result.browsers)}
    item{MonitoringCard(result.monitoring)}
    item{ThreatIntelCard()}
   }
  }
 }
}

@Composable
private fun AppCard(vm:SecurityViewModel,app:InstalledAppInfo){
 var expanded by remember(app.packageName){mutableStateOf(false)}
 Card{Column(Modifier.padding(14.dp),verticalArrangement=Arrangement.spacedBy(5.dp)){
  Text(app.appName,style=MaterialTheme.typography.titleMedium)
  Text("Risco ${app.riskScore}/100 • ${app.riskLevel.label}")
  Text(app.packageName,style=MaterialTheme.typography.bodySmall)
  if(app.adwareLevel!=AdwareLevel.NONE)Text("🟠 ${app.adwareLevel.label}: ${app.adwareScore}/100")
  Row(horizontalArrangement=Arrangement.spacedBy(8.dp)){Text(app.origin.label);Text(if(app.enabled)"Ativo" else "Desativado")}
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
   ActionButtons(vm,app)
   if(app.adwareIndicators.isNotEmpty()){
    Text("Indicadores de possível adware",style=MaterialTheme.typography.titleSmall)
    app.adwareIndicators.forEach{Text("• ${it.title} (+${it.points}) — ${it.detail}",style=MaterialTheme.typography.bodySmall)}
   }
   Text("Permissões sensíveis",style=MaterialTheme.typography.titleSmall)
   if(app.requestedPermissions.isEmpty())Text("Nenhuma das permissões monitoradas foi declarada.")
   app.requestedPermissions.forEach{p->Text("${if(p.granted)"✓" else "○"} ${p.label} — ${if(p.granted)"concedida" else "não concedida"}")}
  }
 }}
}

@Composable
private fun MonitoringCard(status:MonitoringStatus){
 Card{Column(Modifier.padding(14.dp),verticalArrangement=Arrangement.spacedBy(7.dp)){
  Text("Detector de Monitoramento",style=MaterialTheme.typography.titleLarge)
  Text(status.level.label)
  Text("O resultado indica configurações e sinais observáveis; não prova, sozinho, que alguém esteja espionando o aparelho.")
  status.findings.forEach{Text("• ${it.title}: ${it.detail}",style=MaterialTheme.typography.bodySmall)}
  if(status.findings.isEmpty()) Text("Nenhum indicador relevante foi encontrado na análise atual.")
 }
 }
}
@Composable
private fun ThreatIntelCard(){
 var expanded by remember{mutableStateOf(false)}
 Card{Column(Modifier.padding(14.dp),verticalArrangement=Arrangement.spacedBy(7.dp)){
  Text("Inteligência de ameaças Android",style=MaterialTheme.typography.titleLarge)
  Text("Pesquisa atualizada em "+ThreatCatalog.lastResearch+". A lista orienta a análise de comportamento; não é uma assinatura antivírus.")
  ThreatCatalog.threats.take(if(expanded)ThreatCatalog.threats.size else 4).forEach{t->
   Text(t.name,style=MaterialTheme.typography.titleMedium)
   Text(t.category+" • Vetor: "+t.vectors,style=MaterialTheme.typography.bodySmall)
   Text("Comportamento: "+t.behaviors,style=MaterialTheme.typography.bodySmall)
   Text("Foco do scanner: "+t.detectionFocus,style=MaterialTheme.typography.bodySmall)
  }
  TextButton(onClick={expanded=!expanded}){Text(if(expanded)"OCULTAR AMEAÇAS" else "VER AMEAÇAS E MÉTODOS")}
 }}
}
@Composable
private fun ActionButtons(vm:SecurityViewModel,app:InstalledAppInfo){
 Column(verticalArrangement=Arrangement.spacedBy(6.dp)){
  Text("Ferramentas de segurança",style=MaterialTheme.typography.titleSmall)
  Row(horizontalArrangement=Arrangement.spacedBy(6.dp)){
   if(!app.isSystemApp)Button(onClick={vm.open(vm.uninstall(app.packageName))},modifier=Modifier.weight(1f)){Text("DESINSTALAR")}
   Button(onClick={vm.open(vm.appDetails(app.packageName))},modifier=Modifier.weight(1f)){Text("REVISAR APP")}
  }
  Row(horizontalArrangement=Arrangement.spacedBy(6.dp)){
   Button(onClick={vm.open(vm.notificationSettings(app.packageName))},modifier=Modifier.weight(1f)){Text("NOTIFICAÇÕES")}
   Button(onClick={vm.open(vm.permissions(app.packageName))},modifier=Modifier.weight(1f)){Text("CONFIGURAÇÕES")}
  }
  Text("O Android confirma ações sensíveis. O MP Android Security não remove ou bloqueia outro app silenciosamente.",style=MaterialTheme.typography.bodySmall)
 }
}
@Composable
private fun GuidedToolsCard(vm:SecurityViewModel){
 Card{Column(Modifier.padding(14.dp),verticalArrangement=Arrangement.spacedBy(7.dp)){
  Text("Ferramentas guiadas",style=MaterialTheme.typography.titleLarge)
  Text("Acesse as telas oficiais do Android para revisar permissões, acessibilidade e administradores.")
  Button(onClick={vm.open(vm.accessibilitySettings())},modifier=Modifier.fillMaxWidth()){Text("REVISAR ACESSIBILIDADE")}
  Button(onClick={vm.open(vm.deviceAdminSettings())},modifier=Modifier.fillMaxWidth()){Text("REVISAR ADMINISTRADORES")}
 }}
}
@Composable
private fun EmergencyCard(vm:SecurityViewModel){
 Card{Column(Modifier.padding(14.dp),verticalArrangement=Arrangement.spacedBy(7.dp)){
  Text("🚨 MODO DE EMERGÊNCIA",style=MaterialTheme.typography.titleLarge)
  Text("Use quando o aparelho estiver abrindo propaganda, exibindo telas sobre outros apps ou apresentando comportamento anormal.")
  Button(onClick={vm.open(vm.accessibilitySettings())},modifier=Modifier.fillMaxWidth()){Text("1. VERIFICAR ACESSIBILIDADE")}
  Button(onClick={vm.open(vm.deviceAdminSettings())},modifier=Modifier.fillMaxWidth()){Text("2. VERIFICAR ADMINISTRADORES")}
  Button(onClick={vm.open(vm.emergencySettings())},modifier=Modifier.fillMaxWidth()){Text("3. ABRIR CONFIGURAÇÕES")}
 }}
}

@Composable
private fun AdwareRemovalAssistant(vm:SecurityViewModel,result:ScanResult?){
 val targets=result?.apps?.filter{it.adwareLevel!=AdwareLevel.NONE}.orEmpty()
 Card{Column(Modifier.padding(14.dp),verticalArrangement=Arrangement.spacedBy(8.dp)){
  Text("Assistente de Remoção de Adware",style=MaterialTheme.typography.titleLarge)
  Text(if(targets.isEmpty())"Faça uma análise para localizar aplicativos com indicadores de possível adware." else "Siga as etapas para cada aplicativo com indicadores. O Android confirma ações sensíveis.")
  targets.take(5).forEach{app->
   Text("${app.appName} • ${app.adwareLevel.label} (${app.adwareScore}/100)",style=MaterialTheme.typography.titleMedium)
   Text("1. Detectar: ${app.adwareIndicators.size} indicador(es) encontrado(s).",style=MaterialTheme.typography.bodySmall)
   Button(onClick={vm.open(vm.appDetails(app.packageName))},modifier=Modifier.fillMaxWidth()){Text("2. REVISAR PERMISSÕES")}
   if(app.accessibilityEnabled) Button(onClick={vm.open(vm.accessibilitySettings())},modifier=Modifier.fillMaxWidth()){Text("3. DESATIVAR ACESSIBILIDADE")}
   if(app.deviceAdminActive) Button(onClick={vm.open(vm.deviceAdminSettings())},modifier=Modifier.fillMaxWidth()){Text("3. DESATIVAR ADMINISTRADOR")}
   if(!app.isSystemApp) Button(onClick={vm.open(vm.uninstall(app.packageName))},modifier=Modifier.fillMaxWidth()){Text("4. ABRIR DESINSTALAÇÃO")}
   Button(onClick={vm.open(vm.safeModeSettings())},modifier=Modifier.fillMaxWidth()){Text("5. ORIENTAR MODO DE SEGURANÇA")}
   Text("Em Modo de Segurança, o Android inicia sem a maioria dos aplicativos de terceiros. Depois de reiniciar nesse modo, tente novamente a desinstalação.",style=MaterialTheme.typography.bodySmall)
   if(!app.isSystemApp) Button(onClick={vm.open(vm.uninstall(app.packageName))},modifier=Modifier.fillMaxWidth()){Text("6. REPETIR DESINSTALAÇÃO")}
   Button(onClick=vm::scan,modifier=Modifier.fillMaxWidth()){Text("7. FAZER NOVA VARREDURA DE CONFIRMAÇÃO")}
   HorizontalDivider()
  }
 }}
}

@Composable
private fun AboutCard(){
 var expanded by remember{mutableStateOf(false)}
 Card{Column(Modifier.padding(14.dp),verticalArrangement=Arrangement.spacedBy(8.dp)){
  Text("Sobre o aplicativo",style=MaterialTheme.typography.titleLarge)
  Text("MP Android Security",style=MaterialTheme.typography.headlineSmall)
  Text("Versão 1.0.0")
  Text("Desenvolvedor: Márcio Adriano Pimentel")
  Text("Finalidade",style=MaterialTheme.typography.titleMedium)
  Text("Ferramenta de diagnóstico e proteção guiada para Android. Analisa aplicativos instalados, permissões sensíveis, acessibilidade, administradores do dispositivo e indicadores de possível adware, oferecendo ações de revisão e remoção pelos recursos oficiais do Android.")
  TextButton(onClick={expanded=!expanded}){Text(if(expanded)"OCULTAR INFORMAÇÕES" else "VER POLÍTICA, REPOSITÓRIO E LICENÇA")}
  if(expanded){
   Text("Política de privacidade",style=MaterialTheme.typography.titleMedium)
   Text("O MP Android Security foi projetado para realizar as análises localmente no dispositivo. A versão atual não envia a lista de aplicativos, permissões ou resultados de análise para um servidor. A ferramenta deve ser usada apenas pelo proprietário ou por técnico autorizado do aparelho.")
   Text("Repositório",style=MaterialTheme.typography.titleMedium)
   Text("github.com/marcioassessoria-dot/mp-android-security")
   Text("Licença",style=MaterialTheme.typography.titleMedium)
   Text("Licença: MIT License")
   Text("O código deste projeto é disponibilizado sob a licença MIT. Consulte o arquivo LICENSE no repositório para o texto integral da licença.")
  }
 }}
}
@Composable
private fun HighRiskHeader(count:Int){
 Card{Column(Modifier.padding(14.dp),verticalArrangement=Arrangement.spacedBy(5.dp)){
  Text("Aplicativos de alto risco",style=MaterialTheme.typography.titleLarge)
  Text("Exibindo somente pontuação heurística de 80/100 ou mais. Essa pontuação não é uma probabilidade de infecção.")
  Text("Encontrados nesta análise: "+count)
 }}
}
@Composable
private fun BrowserCard(browsers:List<InstalledAppInfo>){
 Card{Column(Modifier.padding(14.dp),verticalArrangement=Arrangement.spacedBy(7.dp)){
  Text("Análise de navegadores",style=MaterialTheme.typography.titleLarge)
  Text("Navegadores instalados detectados pelo Android: "+browsers.size+".")
  browsers.forEach{b->
   Text(b.appName,style=MaterialTheme.typography.titleMedium)
   Text(b.packageName+" • "+b.origin.label,style=MaterialTheme.typography.bodySmall)
   Text("Risco heurístico: "+b.riskScore+"/100 • "+b.riskLevel.label)
   Text("Permissões sensíveis concedidas: "+b.requestedPermissions.count{it.granted})
   if(b.accessibilityEnabled) Text("⚠ Acessibilidade ativa")
   if(b.deviceAdminActive) Text("⚠ Administrador ativo")
  }
  Text("Limitação: Android não permite a um app comum ler diretamente histórico, cookies, senhas, abas privadas ou o banco de dados interno de outro navegador. O scanner verifica o aplicativo, permissões e configurações observáveis.",style=MaterialTheme.typography.bodySmall)
 }}
}
