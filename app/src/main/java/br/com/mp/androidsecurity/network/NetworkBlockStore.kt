package br.com.mp.androidsecurity.network

import br.com.mp.androidsecurity.model.NetworkBlockEvent
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

object NetworkBlockStore {
 private val _events=MutableStateFlow<List<NetworkBlockEvent>>(emptyList())
 val events:StateFlow<List<NetworkBlockEvent>> = _events
 fun add(event:NetworkBlockEvent){_events.value=(_events.value+event).takeLast(100)}
 fun clear(){_events.value=emptyList()}
}
