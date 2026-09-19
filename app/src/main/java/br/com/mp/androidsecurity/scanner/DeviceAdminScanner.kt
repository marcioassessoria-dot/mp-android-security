package br.com.mp.androidsecurity.scanner
import android.app.admin.DevicePolicyManager
import android.content.Context
import br.com.mp.androidsecurity.model.DeviceAdminFinding
class DeviceAdminScanner(private val c:Context){fun scan():List<DeviceAdminFinding>{return c.getSystemService(DevicePolicyManager::class.java)?.activeAdmins.orEmpty().map{val l=try{c.packageManager.getApplicationLabel(c.packageManager.getApplicationInfo(it.packageName,0)).toString()}catch(_:Exception){it.packageName};DeviceAdminFinding(it.packageName,it.className,l)}}}