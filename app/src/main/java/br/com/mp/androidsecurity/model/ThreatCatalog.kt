package br.com.mp.androidsecurity.model

data class ThreatIntel(val name:String,val category:String,val vectors:String,val behaviors:String,val detectionFocus:String,val updated:String,val packageNames:List<String> = emptyList(),val certificateSha256:List<String> = emptyList(),val apkSha256:List<String> = emptyList())

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
  ThreatIntel("NFC relay (SuperCard X, PhantomCard, NGate)","Fraude NFC","Engenharia social e manipulação de sessões NFC","Relé de comunicação NFC para tentar viabilizar fraude de pagamentos","Estado/uso de NFC + sinais de fraude","2026"),
  ThreatIntel("Android.MagicAd.1","Trojan / adware","Apps distribuídos por catálogos de terceiros; identificado também em apps de jogos","Exibe anúncios em segundo plano contornando restrições do Android","Apps de origem alternativa + comportamento de anúncios em segundo plano + sinais de persistência","Jun/2026"),
  ThreatIntel("Aftercall","Adware / campanha de anúncios","Apps que se disfarçam de alarmes, calendários, limpadores e ferramentas; observados no Google Play","Exibe anúncios em tela cheia após o término de chamadas e pode ocultar o app da lista de recentes","Sobreposição + notificações em tela cheia + apps com função incompatível + contexto pós-chamada","Jul/2026"),
  ThreatIntel("FakeAdsBlock","Trojan / adware","Apps de terceiros que se apresentam como bloqueadores de anúncios","Instala adware, exibe anúncios em tela cheia/notificações/widgets e pode solicitar instalação de apps desconhecidos","Instalação desconhecida + overlay + REQUEST_INSTALL_PACKAGES + notificações suspeitas","2026"),
  ThreatIntel("Adware.Bastion.1.origin","Adware","Apps de otimização do Android","Cria notificações sobre supostos problemas de memória/sistema para induzir visualização de anúncios","App de otimização + notificações promocionais + comportamento anômalo","Q2/2026"),
  ThreatIntel("Android.HiddenAds / MobiDash","Adware","Apps Android distribuídos como aplicativos aparentemente legítimos","Exibição de anúncios intrusivos; famílias conhecidas de adware Android","Overlay + notificações + comportamento de publicidade persistente","2026")
 )
}