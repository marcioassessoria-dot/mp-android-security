package com.mpcallsecurity

import android.content.Context
import android.telecom.Call
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object CallRules {
    private const val PREFS = "mp_call_security"
    private const val BLOCKED = "blocked_numbers"
    private const val ALLOWED = "allowed_numbers"
    private const val PREFIXES = "blocked_prefixes"
    private const val BLOCK_UNKNOWN = "block_unknown"
    private const val BLOCK_PRIVATE = "block_private"
    private const val LOGS = "blocked_logs"
    private const val PIN = "pin"
    private fun prefs(context: Context) = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    fun set(context: Context,key:String,value:Boolean)=prefs(context).edit().putBoolean(key,value).apply()
    fun get(context: Context,key:String,default:Boolean)=prefs(context).getBoolean(key,default)
    fun list(context: Context,key:String):MutableSet<String> = prefs(context).getStringSet(key,emptySet())?.toMutableSet() ?: mutableSetOf()
    fun add(context: Context,key:String,value:String){val s=list(context,key);s.add(normalize(value));prefs(context).edit().putStringSet(key,s).apply()}
    fun remove(context: Context,key:String,value:String){val s=list(context,key);s.remove(normalize(value));prefs(context).edit().putStringSet(key,s).apply()}
    fun normalize(value:String):String=value.filter(Char::isDigit)
    fun setPin(context:Context,pin:String)=prefs(context).edit().putString(PIN,pin.filter(Char::isDigit)).apply()
    fun hasPin(context:Context)=prefs(context).getString(PIN,"").orEmpty().length>=4
    fun checkPin(context:Context,pin:String)=hasPin(context)&&prefs(context).getString(PIN,"")==pin.filter(Char::isDigit)
    fun removePin(context:Context)=prefs(context).edit().remove(PIN).apply()
    fun shouldBlock(context:Context,callDetails:Call.Details):Pair<Boolean,String>{
        if(callDetails.callDirection!=Call.Details.DIRECTION_INCOMING)return false to "not-incoming"
        val raw=callDetails.handle?.schemeSpecificPart.orEmpty();val number=normalize(raw)
        if(list(context,ALLOWED).any{sameNumber(number,it)})return false to "allowed"
        val privateNumber=raw.isBlank()||number.isBlank()
        if(privateNumber&&get(context,BLOCK_PRIVATE,false))return true to "privado"
        if(privateNumber&&get(context,BLOCK_UNKNOWN,false))return true to "desconhecido"
        if(list(context,BLOCKED).any{sameNumber(number,it)})return true to "lista negra"
        if(list(context,PREFIXES).any{it.isNotBlank()&&number.startsWith(it)})return true to "prefixo"
        return false to "permitida"
    }
    private fun sameNumber(a:String,b:String):Boolean{if(a.isBlank()||b.isBlank())return false;if(a==b)return true;return a.length>=10&&b.length>=10&&a.takeLast(11)==b.takeLast(11)}
    fun addLog(context:Context,number:String,reason:String){val time=SimpleDateFormat("dd/MM/yyyy HH:mm",Locale.getDefault()).format(Date());val item="$time|${number.ifBlank{"Privado/Desconhecido"}}|$reason";val logs=prefs(context).getStringSet(LOGS,emptySet()).toMutableSet();logs.add(item);prefs(context).edit().putStringSet(LOGS,logs.sortedDescending().take(100).toSet()).apply()}
    fun logs(context:Context):List<String> = prefs(context).getStringSet(LOGS,emptySet())?.sortedDescending()?:emptyList()
    fun clearLogs(context:Context)=prefs(context).edit().remove(LOGS).apply()
}
