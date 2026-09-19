package br.com.mp.androidsecurity.scanner
import android.content.Context
import br.com.mp.androidsecurity.model.ScanResult
import kotlin.system.measureTimeMillis
class LocalSecurityScanner(c:Context){private val apps=InstalledAppsScanner(c);private val acc=AccessibilityScanner(c);private val admins=DeviceAdminScanner(c);fun scan():ScanResult{lateinit var a:List<br.com.mp.androidsecurity.model.AccessibilityFinding>;lateinit var d:List<br.com.mp.androidsecurity.model.DeviceAdminFinding>;lateinit var p:List<br.com.mp.androidsecurity.model.InstalledAppInfo>;val ms=measureTimeMillis{a=acc.scan();d=admins.scan();p=apps.scan(a.map{it.packageName}.toSet(),d.map{it.packageName}.toSet())};return ScanResult(p,a,d,ms)}}