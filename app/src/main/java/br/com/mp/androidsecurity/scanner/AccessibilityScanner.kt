package br.com.mp.androidsecurity.scanner
import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.view.accessibility.AccessibilityManager
import br.com.mp.androidsecurity.model.AccessibilityFinding
class AccessibilityScanner(private val c:Context){fun scan():List<AccessibilityFinding>{val m=c.getSystemService(AccessibilityManager::class.java);return m?.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK).orEmpty().mapNotNull{val s=it.resolveInfo?.serviceInfo?:return@mapNotNull null;AccessibilityFinding(s.packageName,s.name,s.loadLabel(c.packageManager).toString())}.distinctBy{it.packageName+it.serviceName}}}