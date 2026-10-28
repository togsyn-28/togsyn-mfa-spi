package com.togsyn.tech.keycloak.mfa;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.net.URI;
import java.util.Map;

public class MfaUiPasskeyAuthenticator implements Authenticator {



    @Override
    public void authenticate(AuthenticationFlowContext ctx) {
        AuthenticationSessionModel as = ctx.getAuthenticationSession();
        SingleUseObjectProvider store = ctx.getSession().singleUseObjects();
        String rootId = as.getParentSession().getId();

        String ticket = as.getAuthNote(MfaKeys.NOTE_TICKET);
        if (ticket != null) {
            Map<String, String> done = store.remove(MfaKeys.DONE + ticket);   // atomic, single use
            if (done != null && rootId.equals(done.get("rootSessionId"))) {
                UserModel user = ctx.getSession().users().getUserById(ctx.getRealm(), done.get("userId"));
                if (user != null && user.isEnabled()) {
                    store.remove(MfaKeys.TICKET + ticket);
                    as.removeAuthNote(MfaKeys.NOTE_TICKET);
                    ctx.setUser(user);
                    ctx.success();
                    return;
                }
            }
        }
        // ...otherwise (re)issue a ticket and redirect to /passkey-login, as before,
        // storing it under MfaKeys.TICKET + ticket and setting the NOTE_TICKET auth note.
        ticket = SecretGenerator.getInstance().randomString(43);

        String resumeUrl = ctx.getActionUrl(ctx.generateAccessCode()).toString();

        store.put(
                MfaKeys.TICKET + ticket,
                300,
                Map.of(
                        "rootSessionId", rootId,
                        "tabId", as.getTabId(),
                        "clientId", as.getClient().getClientId(),
                        "resumeUrl", resumeUrl
                )
        );

        as.setAuthNote(MfaKeys.NOTE_TICKET, ticket);

        URI ui = UriBuilder.fromUri("http://localhost:5173/passkey-login")
                .queryParam("ticket", ticket)
                .build();

        ctx.challenge(Response.seeOther(ui).build());
    }


    @Override public void action(AuthenticationFlowContext ctx) { authenticate(ctx); }
    @Override public boolean requiresUser() { return false; }
    @Override public boolean configuredFor(KeycloakSession s, RealmModel r, UserModel u) { return true; }
    @Override public void setRequiredActions(KeycloakSession s, RealmModel r, UserModel u) {}
    @Override public void close() {}
}
