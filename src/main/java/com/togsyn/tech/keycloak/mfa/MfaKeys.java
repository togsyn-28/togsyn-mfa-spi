package com.togsyn.tech.keycloak.mfa;


public final class MfaKeys {
    private MfaKeys() {}
    public static final String TICKET = "mfa.ticket.";   // value: rootSessionId, tabId, clientId, resumeUrl
    public static final String LOCK   = "mfa.lock.";     // one completion per ticket
    public static final String DONE   = "mfa.done.";     // value: userId, rootSessionId
    public static final String NOTE_TICKET = "mfa.ticket";            // auth session note
    public static final String NOTE_METHOD = "mfa.method";            // user session note
    public static final String PASSKEY_LOGIN = "mfa.passkeylogin.";  // value: userId
}
