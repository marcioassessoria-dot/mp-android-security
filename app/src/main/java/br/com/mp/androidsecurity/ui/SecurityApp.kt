package br.com.mp.androidsecurity.ui
import android.text.format.DateFormat
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import br.com.mp.androidsecurity.model.*
import br.com.mp.androidsecurity.network.NetworkBlockStore
@OptIn(ExperimentalMaterial3Api::class)
@Composable fun SecurityApp(vm:SecurityViewModel){
 val state by vm.state.collectAsState();val threatIntel by vm.threatIntel.collectAsState();val events by NetworkBlockStore.events.collectAsState();val launcher=rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()){if(it.resultCode==android.app.Activity.RESULT_OK)vm.startAdBlock()}
 Scaffold(topBar={TopAppBar(title={Text("MP Android Security")})}){pad->LazyColumn(Modifier.fillMaxSize().padding(pad).padding(16.dp),verticalArrangement=Arrangement.spacedBy(10.dp)){
  item{Text("Central de diagnóstico e proteção",style=MaterialTheme.typography.headlineSmall);Text("Scanner local para assistência técnica e diagnóstico guiado.")}
  item{Button(onClick=vm::scan,enabled=!state.scanning,modifier=Modifier.fillMaxWidth()){Text(if(state.scanning)"ANALISANDO..." else "ANÁLISE COMPLETA")}}
  item{QuickActions(vm,state.result,events,launcher)}
  item{AboutCard()}
  state.error?.let{item{Text("Erro: "+it,color=MaterialTheme.colorScheme.error)}}
  state.result?.let{r->
   item{SummaryCard(r)};item{OnlineScannerCard(vm,r)};item{DiagnosticsCard(r.diagnostics)};item{PrivateDnsCard(vm,r.privateDns)};item{NetworkProtectionCard(vm,launcher,events)};item{MonitoringCard(r.monitoring)};item{AdwareRemovalAssistant(vm,r)}
   val high=r.apps.filter{it.riskScore>=80};item{HighRiskHeader(high.size)};items(high,key={it.packageName}){AppCard(vm,it)}
   item{BrowserCard(r.browsers)};item{ThreatIntelCard(vm,threatIntel)}
  }
 }}
}
@Composable private fun QuickActions(vm:SecurityViewModel,result:ScanResult?,events:List<NetworkBlockEvent>,launcher:androidx.activity.result.ActivityResultLauncher<android.content.Intent>){Card{Column(Modifier.padding(14.dp),verticalArrangement=Arrangement.spacedBy(7.dp)){Text("Ações rápidas",style=MaterialTheme.typography.titleLarge);Button(onClick=vm::scan,modifier=Modifier.fillMaxWidth()){Text("DIAGNÓSTICO RÁPIDO")};if(result!=null)Button(onClick={vm.shareReport(result,events)},modifier=Modifier.fillMaxWidth()){Text("GERAR RELATÓRIO PDF")};Button(onClick={vm.open(vm.accessibilitySettings())},modifier=Modifier.fillMaxWidth()){Text("REVISAR ACESSIBILIDADE")};Button(onClick={vm.open(vm.deviceAdminSettings())},modifier=Modifier.fillMaxWidth()){Text("REVISAR ADMINISTRADORES")}}}}
@Composable private fun SummaryCard(r:ScanResult){Card{Column(Modifier.padding(14.dp),verticalArrangement=Arrangement.spacedBy(5.dp)){Text("Resumo",style=MaterialTheme.typography.titleLarge);Text("Aplicativos: ${r.apps.size}");Text("Risco ≥80: ${r.highRiskCount} • Suspeitos: ${r.suspiciousCount}");Text("Atenção: ${r.attentionCount} • Baixo: ${r.lowRiskCount}");Text("Possível adware: ${r.possibleAdwareCount} • Alto indício: ${r.highAdwareCount}");Text("Acessibilidade: ${r.accessibility.size} • Administradores: ${r.deviceAdmins.size}")
Text("Correspondências de Threat Intelligence: ${r.threatMatchCount}");Text("Monitoramento: ${r.monitoring.level.label}");Text("Tempo: ${r.durationMs} ms")}}}
@Composable private fun OnlineScannerCard(vm:SecurityViewModel,r:ScanResult){
 val state by vm.state.collectAsState()
 Card{Column(Modifier.padding(14.dp),verticalArrangement=Arrangement.spacedBy(7.dp)){
  Text("Scanner antivírus online",style=MaterialTheme.typography.titleLarge)
  Text("MetaDefender Cloud: consulta por SHA-256 e, quando o hash não é conhecido, envia o APK para análise por múltiplos motores.")
  OutlinedTextField(value=state.metaDefenderApiKey,onValueChange=vm::setMetaDefenderApiKey,label={Text("API key MetaDefender")},singleLine=true,modifier=Modifier.fillMaxWidth())
  Text("A chave não é incorporada ao APK nem enviada para outro servidor pelo MP Security.",style=MaterialTheme.typography.bodySmall)
  if(state.onlineScanningPackage!=null)Text("Analisando \${state.onlineScanningPackage} online...")
  state.onlineError?.let{Text(it,color=MaterialTheme.colorScheme.error,style=MaterialTheme.typography.bodySmall)}
  val results=state.onlineResults
  Text("Apps analisados online: \${results.size}")
  results.values.takeLast(5).forEach{res->
   Text("\${res.verdict} • \${res.detected?.toString()?:"?"}/\${res.totalEngines?.toString()?:"?"} engines",style=MaterialTheme.typography.titleMedium)
   Text(res.details,style=MaterialTheme.typography.bodySmall)
  }
  Text("Importante: o serviço externo pode receber o APK enviado. Use apenas com uma conta/licença compatível e evite enviar arquivos com dados pessoais.",style=MaterialTheme.typography.bodySmall)
 }}
}
@Composable private fun DiagnosticsCard(d:DeviceDiagnostics){Card{Column(Modifier.padding(14.dp),verticalArrangement=Arrangement.spacedBy(5.dp)){Text("Saúde do dispositivo",style=MaterialTheme.typography.titleLarge);Text("${d.manufacturer} ${d.model} • Android ${d.androidVersion} / SDK ${d.sdk}");Text("Patch de segurança: ${d.securityPatch?:"não identificado"}");Text("RAM total: ${d.ramMb} MB");Text("Armazenamento: ${d.storageFreeMb} MB livres de ${d.storageTotalMb} MB");Text("Bateria: ${d.batteryPercent?.let{"$it%"}?:"não identificado"} • ${if(d.charging==true)"carregando" else "não carregando"}");Text("VPN: ${if(d.vpnActive)"ativa" else "não ativa"} • ADB: ${if(d.adbEnabled)"ativo" else "desativado"}");Text("Opções de desenvolvedor: ${if(d.developerOptions)"ativas" else "desativadas"}")}}}
@Composable private fun PrivateDnsCard(vm:SecurityViewModel,s:PrivateDnsStatus){Card{Column(Modifier.padding(14.dp),verticalArrangement=Arrangement.spacedBy(6.dp)){Text("DNS privado",style=MaterialTheme.typography.titleLarge);Text("Status: ${s.state.label}");Text("Provedor: ${s.provider?:"não identificado"}");if(s.isAdGuard)Text("✓ AdGuard DNS identificado");Text(s.detail,style=MaterialTheme.typography.bodySmall);Button(onClick={vm.open(vm.privateDnsSettings())},modifier=Modifier.fillMaxWidth()){Text("ABRIR CONFIGURAÇÕES DE DNS")}}}}
@Composable private fun NetworkProtectionCard(vm:SecurityViewModel,launcher:androidx.activity.result.ActivityResultLauncher<android.content.Intent>,events:List<NetworkBlockEvent>){val byApp=events.groupingBy{it.appName?:"Aplicativo não identificado"}.eachCount().entries.sortedByDescending{it.value}.take(5);Card{Column(Modifier.padding(14.dp),verticalArrangement=Arrangement.spacedBy(7.dp)){Text("Rede e bloqueador",style=MaterialTheme.typography.titleLarge);Text("Bloqueio DNS local com atribuição por UID quando o Android fornece essa informação.");Text("Bloqueios registrados: ${events.size}");Row(horizontalArrangement=Arrangement.spacedBy(7.dp)){Button(onClick={val i=vm.vpnPrepare();if(i==null)vm.startAdBlock()else launcher.launch(i)},modifier=Modifier.weight(1f)){Text("ATIVAR")};OutlinedButton(onClick=vm::stopAdBlock,modifier=Modifier.weight(1f)){Text("DESATIVAR")}};if(byApp.isNotEmpty()){Text("Aplicativos com mais bloqueios",style=MaterialTheme.typography.titleMedium);byApp.forEach{Text("• ${it.key}: ${it.value}")}};events.takeLast(12).asReversed().forEach{e->Text("• ${e.appName?:"Não identificado"} — ${e.domain}",style=MaterialTheme.typography.bodySmall);Text("  ${e.packageName?:"UID "+e.uid}",style=MaterialTheme.typography.bodySmall);Row{TextButton(onClick={vm.blockDomain(e.domain)}){Text("BLOQUEAR")};TextButton(onClick={vm.allowDomain(e.domain)}){Text("PERMITIR")}}};if(events.isNotEmpty())TextButton(onClick=vm::clearNetworkEvents){Text("LIMPAR HISTÓRICO")};Text("Limitações: DoH/DoT, outra VPN e mecanismos fora do DNS interceptado podem não aparecer. Isso não é inspeção completa de tráfego.",style=MaterialTheme.typography.bodySmall)}}}
@Composable private fun MonitoringCard(s:MonitoringStatus){Card{Column(Modifier.padding(14.dp),verticalArrangement=Arrangement.spacedBy(6.dp)){Text("Detector de monitoramento",style=MaterialTheme.typography.titleLarge);Text(s.level.label);Text("Indicadores observáveis não provam, sozinhos, espionagem.");s.findings.forEach{Text("• ${it.title}: ${it.detail}",style=MaterialTheme.typography.bodySmall)};if(s.findings.isEmpty())Text("Nenhum indicador relevante.")}}}
@Composable private fun AdwareRemovalAssistant(vm:SecurityViewModel,r:ScanResult){val targets=r.apps.filter{it.adwareLevel!=AdwareLevel.NONE}.take(8);Card{Column(Modifier.padding(14.dp),verticalArrangement=Arrangement.spacedBy(6.dp)){Text("Assistente de remoção de adware",style=MaterialTheme.typography.titleLarge);if(targets.isEmpty())Text("Nenhum aplicativo apresentou indicadores suficientes para entrar nesta lista.") else targets.forEach{a->Text("${a.appName} • ${a.adwareLevel.label} (${a.adwareScore}/100)",style=MaterialTheme.typography.titleMedium);Text("Indicadores: ${a.adwareIndicators.size}");Button(onClick={vm.open(vm.appDetails(a.packageName))},modifier=Modifier.fillMaxWidth()){Text("REVISAR APP")};if(!a.isSystemApp)Button(onClick={vm.open(vm.uninstall(a.packageName))},modifier=Modifier.fillMaxWidth()){Text("ABRIR DESINSTALAÇÃO")};HorizontalDivider()}}}}
@Composable private fun AppCard(vm:SecurityViewModel,a:InstalledAppInfo){val state by vm.state.collectAsState();var expanded by remember(a.packageName){mutableStateOf(false)};Card{Column(Modifier.padding(14.dp),verticalArrangement=Arrangement.spacedBy(5.dp)){Text(a.appName,style=MaterialTheme.typography.titleMedium);Text("Risco ${a.riskScore}/100 • ${a.riskLevel.label}");Text(a.packageName,style=MaterialTheme.typography.bodySmall);Text(a.origin.label+" • "+if(a.enabled)"Ativo" else "Desativado");if(a.adwareLevel!=AdwareLevel.NONE)Text("Adware: ${a.adwareLevel.label} • ${a.adwareScore}/100")
if(a.threatMatches.isNotEmpty()){Text("Threat Intelligence",style=MaterialTheme.typography.titleSmall);a.threatMatches.take(3).forEach{m->Text("⚠ ${m.threatName} • ${m.confidence}% • ${m.matchedOn.joinToString(", ")}",style=MaterialTheme.typography.bodySmall)}};a.riskReasons.take(if(expanded)10 else 3).forEach{Text("• $it",style=MaterialTheme.typography.bodySmall)};TextButton(onClick={expanded=!expanded}){Text(if(expanded)"OCULTAR" else "VER ANÁLISE DO APP")};if(expanded){
 val online=state.onlineResults[a.packageName]
 Button(onClick={vm.scanOnline(a)},enabled=state.onlineScanningPackage==null,modifier=Modifier.fillMaxWidth()){Text(if(state.onlineScanningPackage==a.packageName)"ANALISANDO ONLINE..." else "VERIFICAR COM ANTIVÍRUS ONLINE")}
 online?.let{Text("Online: \${it.verdict} • \${it.detected?.toString()?:"?"}/\${it.totalEngines?.toString()?:"?"} engines");Text(it.details,style=MaterialTheme.typography.bodySmall)}
 Text("Versão: ${a.versionName?:"desconhecida"} (${a.versionCode})");Text("Instalador: ${a.installer?:"desconhecido"}");Text("Target SDK: ${a.targetSdk}");Text("Instalado: "+DateFormat.format("dd/MM/yyyy HH:mm",a.firstInstallTime));Text("Atualizado: "+DateFormat.format("dd/MM/yyyy HH:mm",a.lastUpdateTime));if(a.accessibilityEnabled)Text("⚠ Acessibilidade ativa");if(a.deviceAdminActive)Text("⚠ Administrador ativo");a.adwareIndicators.forEach{Text("• ${it.title}: ${it.detail}",style=MaterialTheme.typography.bodySmall)};Text("Permissões sensíveis",style=MaterialTheme.typography.titleSmall);a.requestedPermissions.forEach{p->Text("${if(p.granted)"✓" else "○"} ${p.label}")};Row{if(!a.isSystemApp)Button(onClick={vm.open(vm.uninstall(a.packageName))}){Text("DESINSTALAR")};Button(onClick={vm.open(vm.appDetails(a.packageName))}){Text("REVISAR")}}}}}}
@Composable private fun HighRiskHeader(n:Int){Card{Column(Modifier.padding(14.dp)){Text("Aplicativos de alto risco",style=MaterialTheme.typography.titleLarge);Text("Exibindo somente pontuação heurística de 80/100 ou mais. Não é probabilidade de infecção.");Text("Encontrados: $n")}}}
@Composable private fun BrowserCard(b:List<InstalledAppInfo>){Card{Column(Modifier.padding(14.dp),verticalArrangement=Arrangement.spacedBy(6.dp)){Text("Navegadores analisados",style=MaterialTheme.typography.titleLarge);Text("Detectados: ${b.size}");b.forEach{Text("${it.appName} • ${it.riskScore}/100 • ${it.origin.label}");Text("Permissões sensíveis concedidas: ${it.requestedPermissions.count{p->p.granted}}",style=MaterialTheme.typography.bodySmall)};Text("O Android não permite a um app comum ler histórico, cookies, senhas ou banco privado de outro navegador.",style=MaterialTheme.typography.bodySmall)}}}
@Composable private fun ThreatIntelCard(vm:SecurityViewModel,state:br.com.mp.androidsecurity.threat.ThreatIntelState){
 var expanded by remember{mutableStateOf(false)}
 Card{Column(Modifier.padding(14.dp),verticalArrangement=Arrangement.spacedBy(6.dp)){
  Text("Inteligência de ameaças",style=MaterialTheme.typography.titleLarge)
  Text("Fonte: "+state.source)
  Text("Versão do feed: "+state.version+" • Atualizado: "+state.updatedAt)
  if(state.syncing)Text("Sincronizando...")
  state.error?.let{Text("Sincronização: "+it,color=MaterialTheme.colorScheme.error,style=MaterialTheme.typography.bodySmall)}
  state.threats.take(if(expanded)state.threats.size else 4).forEach{Text(it.name,style=MaterialTheme.typography.titleMedium);Text(it.category+" • "+it.vectors,style=MaterialTheme.typography.bodySmall)}
  Row(horizontalArrangement=Arrangement.spacedBy(7.dp)){
   TextButton(onClick={expanded=!expanded}){Text(if(expanded)"OCULTAR" else "VER AMEAÇAS")}
   OutlinedButton(onClick=vm::syncThreatIntel,enabled=!state.syncing){Text("ATUALIZAR")}
  }
  Text("O catálogo orienta a análise; não é assinatura antivírus e não prova infecção.",style=MaterialTheme.typography.bodySmall)
 }}
}
@Composable private fun AboutCard(){Card{Column(Modifier.padding(14.dp),verticalArrangement=Arrangement.spacedBy(5.dp)){Text("Sobre",style=MaterialTheme.typography.titleLarge);Text("MP Android Security 1.0.0");Text("Ferramenta local de diagnóstico e proteção guiada para Android. Não envia a lista de aplicativos ou resultados para servidor na versão atual.");Text("Desenvolvedor: Márcio Adriano Pimentel")}}}