package br.com.mp.androidsecurity.report
import android.content.Context
import android.graphics.Paint
import android.graphics.pdf.PdfDocument
import android.net.Uri
import androidx.core.content.FileProvider
import br.com.mp.androidsecurity.model.ScanResult
import br.com.mp.androidsecurity.model.NetworkBlockEvent
import java.io.File
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
object ReportGenerator{
 fun createPdf(c:Context,r:ScanResult,events:List<NetworkBlockEvent>):Uri{
  val dir=File(c.cacheDir,"reports").apply{mkdirs()};val file=File(dir,"mp-android-security-${System.currentTimeMillis()}.pdf");val doc=PdfDocument();var page=doc.startPage(PdfDocument.PageInfo.Builder(595,842,1).create());val paint=Paint().apply{textSize=11f};var y=36f
  fun line(s:String){if(y>805){doc.finishPage(page);page=doc.startPage(PdfDocument.PageInfo.Builder(595,842,doc.pages.size+1).create());y=36f};page.canvas.drawText(s.take(100),28f,y,paint);y+=17f}
  line("MP ANDROID SECURITY - RELATORIO TECNICO");line("Data: "+SimpleDateFormat("dd/MM/yyyy HH:mm",Locale("pt","BR")).format(Date()));line("Aparelho: "+r.diagnostics.manufacturer+" "+r.diagnostics.model);line("Android: "+r.diagnostics.androidVersion+" (SDK "+r.diagnostics.sdk+")");line("Patch: "+(r.diagnostics.securityPatch?:"não identificado"));line("Risco heurístico >=80: "+r.highRiskCount);line("Possível adware: "+r.possibleAdwareCount+" / alto indício: "+r.highAdwareCount);line("Acessibilidade ativa: "+r.accessibility.size);line("Administradores: "+r.deviceAdmins.size);line("Monitoramento: "+r.monitoring.level.label);line("DNS: "+r.privateDns.state.label+" / "+(r.privateDns.provider?:"não identificado"));line("AdGuard DNS: "+if(r.privateDns.isAdGuard)"sim" else "não");line("VPN ativa: "+if(r.diagnostics.vpnActive)"sim" else "não");line("ADB ativo: "+if(r.diagnostics.adbEnabled)"sim" else "não");line("Opções de desenvolvedor: "+if(r.diagnostics.developerOptions)"sim" else "não");line("ARQUIVOS DE REDE: "+events.size+" bloqueios registrados");
  events.takeLast(30).asReversed().forEach{line("• "+(it.appName?:"Aplicativo não identificado")+" | "+it.domain+" | "+it.reason)}
  line("APLICATIVOS DE ALTO RISCO");r.apps.filter{it.riskScore>=80}.take(30).forEach{line("• "+it.appName+" | "+it.packageName+" | "+it.riskScore+"/100 | "+it.origin.label)}
  line("Observação: a pontuação é heurística e não representa probabilidade de infecção. O relatório registra sinais observáveis no momento da análise.")
  doc.finishPage(page);FileOutputStream(file).use{doc.writeTo(it)};doc.close();return FileProvider.getUriForFile(c,c.packageName+".fileprovider",file)
 }
}