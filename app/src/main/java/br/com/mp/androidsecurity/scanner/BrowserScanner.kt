package br.com.mp.androidsecurity.scanner
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.content.pm.PackageManager
class BrowserScanner(private val c:Context){
 fun scan():Set<String>{
  val i=Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com")).addCategory(Intent.CATEGORY_BROWSABLE)
  return c.packageManager.queryIntentActivities(i,PackageManager.MATCH_ALL).map{it.activityInfo.packageName}.toSet()
 }
}
