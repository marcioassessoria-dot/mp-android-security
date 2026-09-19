package br.com.mp.androidsecurity.network

import br.com.mp.androidsecurity.model.NetworkBlockEvent
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

object NetworkBlockStore{
 private val _events=MutableStateFlow<List<NetworkBlockEvent>>(emptyList()); val events:StateFlow<List<NetworkBlockEvent>>=_events
 private val blocked=mutableSetOf<String>(); private val allowed=mutableSetOf<String>()
 fun add(event:NetworkBlockEvent){_events.value=(_events.value+event).takeLast(500)}
 fun clear(){_events.value=emptyList()}
 fun blockDomain(domain:String){allowed.remove(domain.lowercase());blocked.add(domain.lowercase())}
 fun allowDomain(domain:String){blocked.remove(domain.lowercase());allowed.add(domain.lowercase())}
 fun isBlocked(domain:String):Boolean{val d=domain.lowercase();if(allowed.any{d==it||d.endsWith("." + it)})return false;return blocked.any{d==it||d.endsWith("." + it)}}
 fun blockedDomains():Set<String>=blocked.toSet(); fun allowedDomains():Set<String>=allowed.toSet()
}