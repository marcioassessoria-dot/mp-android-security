package br.com.mp.androidsecurity.call

import android.provider.ContactsContract
import android.telecom.Call
import android.telecom.CallScreeningService
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class CallScreeningServiceImpl : CallScreeningService() {
    override fun onScreenCall(callDetails: Call.Details) {
        val number = callDetails.handle?.schemeSpecificPart.orEmpty()
        val normalized = CallRules.normalize(number)
        val allowed = CallRules.list(this, "allowed_numbers")
        val blocked = CallRules.list(this, "blocked_numbers")
        val prefixes = CallRules.list(this, "blocked_prefixes")
        val privateCall = normalized.isBlank()
        val unknown = normalized.isNotBlank() && !isContact(normalized)
        val shouldBlock = normalized !in allowed && (
            normalized in blocked ||
            prefixes.any { normalized.startsWith(it) } ||
            (CallRules.get(this, "block_unknown", false) && unknown) ||
            (CallRules.get(this, "block_private", false) && privateCall)
        )
        val response = CallScreeningService.CallResponse.Builder()
            .setDisallowCall(shouldBlock)
            .setRejectCall(shouldBlock)
            .setSkipCallLog(false)
            .setSkipNotification(shouldBlock)
            .build()
        respondToCall(callDetails, response)
        if (shouldBlock) {
            val time = SimpleDateFormat("dd/MM/yyyy HH:mm", Locale.getDefault()).format(Date())
            CallRules.addLog(this, "$time • $number")
        }
    }

    private fun isContact(number: String): Boolean {
        val uri = ContactsContract.CommonDataKinds.Phone.CONTENT_FILTER_URI.buildUpon().appendPath(number).build()
        contentResolver.query(uri, arrayOf(ContactsContract.CommonDataKinds.Phone.NUMBER), null, null, null)?.use {
            return it.moveToFirst()
        }
        return false
    }
}
