package com.mpcallsecurity

import android.telecom.Call
import android.telecom.CallScreeningService

class CallScreeningServiceImpl : CallScreeningService() {
    override fun onScreenCall(callDetails: Call.Details) {
        val rawNumber = callDetails.handle?.schemeSpecificPart.orEmpty()
        val (blocked, reason) = CallRules.shouldBlock(this, callDetails)
        if (blocked) CallRules.addLog(this, rawNumber, reason)
        val response = CallResponse.Builder()
            .setDisallowCall(blocked)
            .setRejectCall(blocked)
            .setSkipCallLog(false)
            .setSkipNotification(blocked)
            .build()
        respondToCall(callDetails, response)
    }
}
