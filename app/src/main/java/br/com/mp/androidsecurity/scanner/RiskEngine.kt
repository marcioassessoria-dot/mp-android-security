package br.com.mp.androidsecurity.scanner
import android.Manifest
import br.com.mp.androidsecurity.model.RiskLevel
object RiskEngine{
 private val p=mapOf(Manifest.permission.CAMERA to 5,Manifest.permission.RECORD_AUDIO to 8,Manifest.permission.ACCESS_FINE_LOCATION to 5,Manifest.permission.ACCESS_COARSE_LOCATION to 3,Manifest.permission.READ_CONTACTS to 6,Manifest.permission.READ_SMS to 10,Manifest.permission.SEND_SMS to 10,Manifest.permission.READ_CALL_LOG to 8,Manifest.permission.WRITE_CALL_LOG to 8,Manifest.permission.CALL_PHONE to 8,Manifest.permission.SYSTEM_ALERT_WINDOW to 10,Manifest.permission.REQUEST_INSTALL_PACKAGES to 8,Manifest.permission.READ_PHONE_STATE to 4,Manifest.permission.READ_PHONE_NUMBERS to 4,Manifest.permission.GET_ACCOUNTS to 5)
 private val labels=mapOf(Manifest.permission.CAMERA to "Câmera",Manifest.permission.RECORD_AUDIO to "Microfone",Manifest.permission.ACCESS_FINE_LOCATION to "Localização precisa",Manifest.permission.ACCESS_COARSE_LOCATION to "Localização aproximada",Manifest.permission.READ_CONTACTS to "Ler contatos",Manifest.permission.READ_SMS to "Ler SMS",Manifest.permission.SEND_SMS to "Enviar SMS",Manifest.permission.READ_CALL_LOG to "Ler chamadas",Manifest.permission.WRITE_CALL_LOG to "Alterar chamadas",Manifest.permission.CALL_PHONE to "Fazer chamadas",Manifest.permission.SYSTEM_ALERT_WINDOW to "Sobrepor outras telas",Manifest.permission.REQUEST_INSTALL_PACKAGES to "Instalar pacotes",Manifest.permission.READ_PHONE_STATE to "Estado do telefone",Manifest.permission.READ_PHONE_NUMBERS to "Número do telefone",Manifest.permission.GET_ACCOUNTS to "Contas do dispositivo")
 fun isSensitive(permission:String)=permission in p
 fun points(permission:String)=p[permission]?:0
 fun label(permission:String)=labels[permission]?:permission.substringAfterLast('.')
 fun reasons(req:List<String>,granted:Set<String>,access:Boolean,admin:Boolean):List<String>=buildList{
  granted.filter{it in p}.forEach{add("Permissão sensível: ${label(it)}")}
  if(access)add("Serviço de acessibilidade ativo")
  if(admin)add("Administrador do dispositivo ativo")
  if(Manifest.permission.REQUEST_INSTALL_PACKAGES in granted)add("Pode solicitar instalação de outros APKs")
  if(Manifest.permission.SYSTEM_ALERT_WINDOW in granted)add("Pode exibir conteúdo sobre outros aplicativos")
  if(granted.contains(Manifest.permission.READ_SMS)&&granted.contains(Manifest.permission.SEND_SMS))add("Lê e envia SMS")
 }.distinct()
 fun level(s:Int)=when{ s>=50->RiskLevel.HIGH;s>=30->RiskLevel.SUSPICIOUS;s>=15->RiskLevel.ATTENTION;else->RiskLevel.LOW}
 fun score(req:List<String>,granted:Set<String>,access:Boolean,admin:Boolean)=(req.filter{it in granted}.sumOf(::points)+(if(access)10 else 0)+(if(admin)10 else 0)).coerceAtMost(100)
}