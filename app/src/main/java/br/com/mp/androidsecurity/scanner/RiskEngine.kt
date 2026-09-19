package br.com.mp.androidsecurity.scanner
import android.Manifest
import br.com.mp.androidsecurity.model.*
object RiskEngine{
 private val p=mapOf(Manifest.permission.CAMERA to 5,Manifest.permission.RECORD_AUDIO to 8,Manifest.permission.ACCESS_FINE_LOCATION to 5,Manifest.permission.ACCESS_COARSE_LOCATION to 3,Manifest.permission.READ_CONTACTS to 6,Manifest.permission.READ_SMS to 10,Manifest.permission.SEND_SMS to 10,Manifest.permission.READ_CALL_LOG to 8,Manifest.permission.WRITE_CALL_LOG to 8,Manifest.permission.CALL_PHONE to 8,Manifest.permission.SYSTEM_ALERT_WINDOW to 10,Manifest.permission.REQUEST_INSTALL_PACKAGES to 8,Manifest.permission.READ_PHONE_STATE to 4,Manifest.permission.READ_PHONE_NUMBERS to 4,Manifest.permission.GET_ACCOUNTS to 5)
 private val labels=mapOf(Manifest.permission.CAMERA to "Câmera",Manifest.permission.RECORD_AUDIO to "Microfone",Manifest.permission.ACCESS_FINE_LOCATION to "Localização precisa",Manifest.permission.ACCESS_COARSE_LOCATION to "Localização aproximada",Manifest.permission.READ_CONTACTS to "Ler contatos",Manifest.permission.READ_SMS to "Ler SMS",Manifest.permission.SEND_SMS to "Enviar SMS",Manifest.permission.READ_CALL_LOG to "Ler chamadas",Manifest.permission.WRITE_CALL_LOG to "Alterar chamadas",Manifest.permission.CALL_PHONE to "Fazer chamadas",Manifest.permission.SYSTEM_ALERT_WINDOW to "Sobrepor outras telas",Manifest.permission.REQUEST_INSTALL_PACKAGES to "Instalar pacotes",Manifest.permission.READ_PHONE_STATE to "Estado do telefone",Manifest.permission.READ_PHONE_NUMBERS to "Número do telefone",Manifest.permission.GET_ACCOUNTS to "Contas do dispositivo")
 fun isSensitive(permission:String)=permission in p
 fun points(permission:String)=p[permission]?:0
 fun label(permission:String)=labels[permission]?:permission.substringAfterLast('.')
 fun reasons(req:List<String>,granted:Set<String>,access:Boolean,admin:Boolean): List<String> = buildList {
  granted.filter{it in p}.forEach{add("Permissão sensível: ${label(it)}")}
  if(access)add("Serviço de acessibilidade ativo")
  if(admin)add("Administrador do dispositivo ativo")
  if(Manifest.permission.REQUEST_INSTALL_PACKAGES in granted)add("Pode solicitar instalação de outros APKs")
  if(Manifest.permission.SYSTEM_ALERT_WINDOW in granted)add("Pode exibir conteúdo sobre outros aplicativos")
  if(granted.contains(Manifest.permission.READ_SMS)&&granted.contains(Manifest.permission.SEND_SMS))add("Lê e envia SMS")
 }.distinct()
 fun level(s:Int)=when{ s>=50->RiskLevel.HIGH;s>=30->RiskLevel.SUSPICIOUS;s>=15->RiskLevel.ATTENTION;else->RiskLevel.LOW}
 fun score(req:List<String>,granted:Set<String>,access:Boolean,admin:Boolean)=(req.filter{it in granted}.sumOf(::points)+(if(access)10 else 0)+(if(admin)10 else 0)).coerceAtMost(100)
 fun adwareIndicators(req:List<String>,granted:Set<String>,access:Boolean,installer:String?,firstInstallTime:Long,isSystemApp:Boolean):List<AdwareIndicator>{
  val out=mutableListOf<AdwareIndicator>()
  if(Manifest.permission.SYSTEM_ALERT_WINDOW in granted) out+=AdwareIndicator("Sobreposição de tela","Pode exibir conteúdo por cima de outros aplicativos; combinado com outros sinais, é um indicador de propaganda intrusiva ou fraude.",20)
  if(access) out+=AdwareIndicator("Acessibilidade ativa","Pode ler elementos da tela e automatizar toques; é abusada por algumas ameaças para controlar o aparelho.",20)
  if(Manifest.permission.REQUEST_INSTALL_PACKAGES in granted) out+=AdwareIndicator("Instalação de APKs","Pode solicitar instalação de outros pacotes; aumenta o risco quando combinado com sideloading ou outros indicadores.",15)
  if("android.permission.RECEIVE_BOOT_COMPLETED" in req) out+=AdwareIndicator("Inicialização automática","Pode iniciar após a reinicialização; isoladamente não é malicioso, mas reforça outros sinais.",5)
  if("android.permission.POST_NOTIFICATIONS" in req && "android.permission.SYSTEM_ALERT_WINDOW" in granted) out+=AdwareIndicator("Notificações + sobreposição","A combinação pode ser usada para publicidade intrusiva; investigar se não houver justificativa funcional.",12)
  if("android.permission.USE_FULL_SCREEN_INTENT" in req) out+=AdwareIndicator("Notificação em tela cheia","Pode apresentar conteúdo em tela cheia, inclusive em contexto de bloqueio; avaliar a finalidade do app.",12)
  if("android.permission.READ_PHONE_STATE" in granted && Manifest.permission.SYSTEM_ALERT_WINDOW in granted) out+=AdwareIndicator("Contexto de chamadas + sobreposição","A combinação merece revisão quando anúncios aparecem após ligações.",15)
  if("android.permission.BIND_ACCESSIBILITY_SERVICE" in req && access) out+=AdwareIndicator("Acessibilidade declarada e ativa","Acessibilidade ativa pode ser abusada para automatizar ações e facilitar publicidade ou fraude.",15)
  if(installer.isNullOrBlank()&&!isSystemApp) out+=AdwareIndicator("Instalador não identificado","A origem da instalação não foi identificada; isso pode ocorrer com APKs instalados fora de lojas.",8)
  if(System.currentTimeMillis()-firstInstallTime<=7L*24*60*60*1000&&!isSystemApp) out+=AdwareIndicator("Instalação recente","Instalado nos últimos 7 dias; é apenas contexto e não prova infecção.",5)
  return out
 }
 fun adwareScore(indicators:List<AdwareIndicator>,granted:Set<String>,access:Boolean):Int{
  val combo=when{
   Manifest.permission.SYSTEM_ALERT_WINDOW in granted&&access->20
   Manifest.permission.SYSTEM_ALERT_WINDOW in granted&&Manifest.permission.REQUEST_INSTALL_PACKAGES in granted->15
   access&&Manifest.permission.REQUEST_INSTALL_PACKAGES in granted->15
   else->0
  }
  return (indicators.sumOf{it.points}+combo).coerceAtMost(100)
 }
 fun adwareLevel(score:Int,indicators:List<AdwareIndicator>):AdwareLevel=when{
  indicators.size>=2&&score>=45->AdwareLevel.HIGH
  indicators.size>=2&&score>=25->AdwareLevel.POSSIBLE
  else->AdwareLevel.NONE
 }
}