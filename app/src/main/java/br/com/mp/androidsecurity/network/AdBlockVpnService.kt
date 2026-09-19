package br.com.mp.androidsecurity.network
import android.app.*
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import br.com.mp.androidsecurity.model.NetworkBlockEvent
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.*
import java.util.Locale
class AdBlockVpnService:VpnService(){
 private var vpn:ParcelFileDescriptor?=null;private var thread:Thread?=null
 private val defaults=setOf("doubleclick.net","googlesyndication.com","googleadservices.com","adnxs.com","adsrvr.org","adform.net","taboola.com","outbrain.com","unityads.unity3d.com","app-measurement.com")
 override fun onCreate(){super.onCreate();createChannel()}
 override fun onStartCommand(intent:Intent?,flags:Int,startId:Int):Int{
  if(vpn!=null)return START_STICKY
  if(Build.VERSION.SDK_INT>=34)startForeground(77,notification(),ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE) else startForeground(77,notification())
  vpn=Builder().setSession("MP Android Security").addAddress("10.0.0.2",32).addDnsServer("10.0.0.1").addRoute("10.0.0.1",32).setBlocking(true).establish()
  val fd=vpn?:return START_NOT_STICKY;thread=Thread{loop(fd)}.also{it.start()};return START_STICKY
 }
 private fun loop(fd:ParcelFileDescriptor){val input=FileInputStream(fd.fileDescriptor);val output=FileOutputStream(fd.fileDescriptor);val buf=ByteArray(32767);try{while(!Thread.currentThread().isInterrupted){val n=input.read(buf);if(n<=0)break;val packet=buf.copyOf(n);if(!isDnsQuery(packet))continue;val q=parseQuery(packet)?:continue;val uid=resolveUid(q.srcIp,q.srcPort,q.dstIp,q.dstPort);val app=resolveApp(uid);if(NetworkBlockStore.isBlocked(q.domain)||defaults.any{q.domain==it||q.domain.endsWith("." + it)}){output.write(buildBlockedResponse(packet));NetworkBlockStore.add(NetworkBlockEvent(System.currentTimeMillis(),app?.first,app?.second,q.domain,"Domínio bloqueado por publicidade/rastreamento",uid))}else{forwardDns(q.dnsPayload)?.let{output.write(buildUdpResponse(packet,it))}}}}catch(_:Throwable){}finally{stopSelf()}}
 private data class Query(val srcIp:ByteArray,val dstIp:ByteArray,val srcPort:Int,val dstPort:Int,val dnsPayload:ByteArray,val domain:String)
 private fun isDnsQuery(p:ByteArray):Boolean{if(p.size<28)return false;val ihl=(p[0].toInt() and 15)*4;return (p[9].toInt() and 255)==17&&p.size>=ihl+8&&u16(p,ihl+2)==53}
 private fun parseQuery(p:ByteArray):Query?{val ihl=(p[0].toInt() and 15)*4;val sp=u16(p,ihl);val dp=u16(p,ihl+2);val dns=p.copyOfRange(ihl+8,p.size);if(dns.size<17)return null;val domain=parseQName(dns,12)?:return null;return Query(p.copyOfRange(12,16),p.copyOfRange(16,20),sp,dp,dns,domain)}
 private fun parseQName(d:ByteArray,start:Int):String?{var i=start;val labels=mutableListOf<String>();while(i<d.size){val len=d[i].toInt() and 255;i++;if(len==0)break;if(len>63||i+len>d.size)return null;labels+=String(d,i,len);i+=len};return labels.joinToString(".").lowercase(Locale.US).removeSuffix(".")}
 private fun resolveUid(src:ByteArray,sp:Int,dst:ByteArray,dp:Int):Int{if(Build.VERSION.SDK_INT<29)return -1;return runCatching{getSystemService(android.net.ConnectivityManager::class.java).getConnectionOwnerUid(OsConstants.IPPROTO_UDP,InetSocketAddress(InetAddress.getByAddress(src),sp),InetSocketAddress(InetAddress.getByAddress(dst),dp)).toInt()}.getOrDefault(-1)}
 private fun resolveApp(uid:Int):Pair<String,String>?{if(uid<0)return null;val p=packageManager.getPackagesForUid(uid)?.firstOrNull()?:return null;val n=runCatching{packageManager.getApplicationLabel(packageManager.getApplicationInfo(p,0)).toString()}.getOrDefault(p);return p to n}
 private fun forwardDns(payload:ByteArray):ByteArray?=runCatching{DatagramSocket().use{s->protect(s);s.soTimeout=1500;s.send(DatagramPacket(payload,payload.size,InetAddress.getByName("1.1.1.1"),53));val b=ByteArray(4096);val r=DatagramPacket(b,b.size);s.receive(r);r.data.copyOf(r.length)}}.getOrNull()
 private fun buildBlockedResponse(p:ByteArray):ByteArray{val ihl=(p[0].toInt() and 15)*4;val dns=p.copyOfRange(ihl+8,p.size);dns[2]=(dns[2].toInt() or 0x80).toByte();dns[3]=((dns[3].toInt() and 0xF0) or 0x03).toByte();return buildUdpResponse(p,dns)}
 private fun buildUdpResponse(orig:ByteArray,payload:ByteArray):ByteArray{val ihl=(orig[0].toInt() and 15)*4;val out=ByteArray(ihl+8+payload.size);orig.copyInto(out,0,0,ihl);orig.copyInto(out,12,16,20);orig.copyInto(out,16,12,16);out[9]=17;out[2]=((out.size ushr 8) and 255).toByte();out[3]=(out.size and 255).toByte();out[ihl]=orig[ihl+2];out[ihl+1]=orig[ihl+3];out[ihl+2]=orig[ihl];out[ihl+3]=orig[ihl+1];val len=out.size-ihl-8;out[ihl+4]=(len ushr 8).toByte();out[ihl+5]=len.toByte();out[ihl+6]=0;out[ihl+7]=0;payload.copyInto(out,ihl+8);out[10]=0;out[11]=0;val ip=onesComplementSum(out,0,ihl);out[10]=(ip ushr 8).toByte();out[11]=ip.toByte();val udp=udpChecksum(out,ihl);out[ihl+6]=(udp ushr 8).toByte();out[ihl+7]=udp.toByte();return out}
 private fun udpChecksum(p:ByteArray,ihl:Int):Int{var s=0L;for(i in 12 until 20 step 2)s+=u16(p,i);s+=17;s+=p.size-ihl-8;s+=onesComplementSum(p,ihl,p.size-ihl);while(s ushr 16!=0)s=(s and 65535)+(s ushr 16);val v=s.inv().toInt() and 65535;return if(v==0)65535 else v}
 private fun onesComplementSum(p:ByteArray,start:Int,len:Int):Long{var s=0L;var i=start;val end=start+len;while(i+1<end){s+=u16(p,i);i+=2};if(i<end)s+=(p[i].toInt() and 255) shl 8;while(s ushr 16!=0)s=(s and 65535)+(s ushr 16);return s}
 private fun u16(p:ByteArray,i:Int)=(p[i].toInt() and 255)*256+(p[i+1].toInt() and 255)
 override fun onDestroy(){thread?.interrupt();vpn?.close();vpn=null;super.onDestroy()}
 override fun onRevoke(){stopSelf();super.onRevoke()}
 private fun createChannel(){if(Build.VERSION.SDK_INT>=26)getSystemService(NotificationManager::class.java).createNotificationChannel(NotificationChannel("mp_security","MP Android Security",NotificationManager.IMPORTANCE_LOW))}
 private fun notification():Notification{val b=if(Build.VERSION.SDK_INT>=26)Notification.Builder(this,"mp_security") else Notification.Builder(this);return b.setContentTitle("MP Android Security").setContentText("Proteção DNS local ativa").setSmallIcon(android.R.drawable.ic_secure).build()}
}