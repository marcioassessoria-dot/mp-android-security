package br.com.mp.androidsecurity.model

data class ThreatIntel(val name:String,val category:String,val vectors:String,val behaviors:String,val detectionFocus:String,val updated:String)

object ThreatCatalog{
 const val lastResearch="19/09/2026"
 val threats=listOf(
  ThreatIntel("StreamRat","Trojan bancário / infostealer","Anúncios maliciosos, páginas falsas e APK por sideload","Captura de tela, dados digitados, telas falsas e controle remoto","Sideloading + acessibilidade + sobreposição + controle remoto","Set/2026"),
  ThreatIntel("Gigabud","Trojan bancário","Phishing por SMS, redes sociais e sites falsos","Acessibilidade, sobreposição, perfil de trabalho e clonagem de app bancário","Acessibilidade + overlay + instalação de APK + perfis de trabalho","Set/2026"),
  ThreatIntel("RatHat","Trojan / RAT","Smishing, anúncios maliciosos e páginas falsas","Acessibilidade, Wireless Debugging/ADB e controle remoto automatizado","Acessibilidade + sideloading + sinais de depuração sem fio","Set/2026"),
  ThreatIntel("Manic","Trojan bancário / RAT","Engenharia social e APK malicioso","Acessibilidade, teclado sobreposto, roubo de credenciais e controle remoto","Acessibilidade + overlay + automação","Ago/2026"),
  ThreatIntel("Keenadu","Backdoor / ad fraud","Firmware pré-instalado, apps de sistema comprometidos e alguns casos em lojas","Fraude publicitária, comportamento de bot e potencial controle","Apps de sistema anômalos + origem/assinatura + comportamento","Fev/2026"),
  ThreatIntel("BeatBanker / BTMOB","Trojan bancário / RAT","Apps falsos, incluindo imitações de Starlink e serviços públicos","Persistência, RAT e roubo financeiro; campanha observada no Brasil","Sideloading + persistência + permissões + origem","Mar/2026"),
  ThreatIntel("Triada","Backdoor / malware pré-instalado","Firmware ou cadeia de fornecimento comprometida","Intercepção de dados, SMS e atividade de apps","Integridade do sistema/firmware e apps de sistema","2025–2026"),
  ThreatIntel("NFC relay (SuperCard X, PhantomCard, NGate)","Fraude NFC","Engenharia social e manipulação de sessões NFC","Relé de comunicação NFC para tentar viabilizar fraude de pagamentos","Estado/uso de NFC + sinais de fraude","2026")
 )
}