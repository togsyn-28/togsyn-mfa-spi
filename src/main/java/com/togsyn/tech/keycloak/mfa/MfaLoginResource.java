package com.togsyn.tech.keycloak.mfa;


import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;

import java.util.Map;
import java.util.Set;

public class MfaLoginResource {

    private static final Logger LOG = Logger.getLogger(MfaLoginResource.class);
    private static final long MAX_TOKEN_AGE_SECONDS = 60;
    private static final long DONE_TTL_SECONDS = 60;
    /** Clients whose passkey tokens may complete a ticket. Make this config later. */
    private static final Set<String> ALLOWED_CLIENTS = Set.of("web-app");

    public static class CompleteRequest {
        public String ticket;
    }

    private final KeycloakSession session;

    public MfaLoginResource(KeycloakSession session) {
        this.session = session;
    }

    @OPTIONS
    @Path("complete")
    public Response preflight(@HeaderParam("Origin") String origin) {
        if (!originAllowed(origin)) return Response.status(403).build();
        return cors(origin, Response.noContent()).build();
    }

    @POST
    @Path("complete")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response complete(@HeaderParam("Origin") String origin, CompleteRequest req) {
        if (!originAllowed(origin)) return Response.status(403).build();
        if (req == null || req.ticket == null || req.ticket.isBlank()) return error(origin, 400, "invalid_request");

        // 1. Who is calling? A valid bearer token from this realm.
        AuthenticationManager.AuthResult auth = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
        if (auth == null) return error(origin, 401, "unauthorized");

        AccessToken token = auth.getToken();
        UserModel user = auth.getUser();
        RealmModel realm = session.getContext().getRealm();

        SingleUseObjectProvider store = session.singleUseObjects();

        String sid = auth.getSession().getId();

        Map<String, String> marker =
                store.get(MfaKeys.PASSKEY_LOGIN + sid);


        // 2. Is it a fresh PASSKEY login, from an allowed client, for a normal enabled user?
        //    (iat, not auth_time: your tokens carry no auth_time claim)
        long age = Time.currentTime() - (token.getIat() == null ? 0 : token.getIat());
        boolean fresh = age >= 0 && age <= MAX_TOKEN_AGE_SECONDS;
        boolean passkey = marker != null && user != null && user.getId().equals(marker.get("userId"));
        boolean clientOk = ALLOWED_CLIENTS.contains(token.getIssuedFor());
        if (!fresh || !passkey || !clientOk
                || user == null || !user.isEnabled() || user.getServiceAccountClientLink() != null) {
            LOG.warnf(
                    "mfa-login complete rejected: fresh=%s passkey=%s clientOk=%s sid=%s",
                    fresh,
                    passkey,
                    clientOk,
                    sid);
            return error(origin, 403, "forbidden");
        }

// 3. Does the ticket exist (issued by the authenticator, not expired)?
        Map<String, String> ticket = store.get(MfaKeys.TICKET + req.ticket);
        if (ticket == null) return error(origin, 400, "invalid_or_expired_ticket");

// 4. One completion per ticket.
        if (!store.putIfAbsent(MfaKeys.LOCK + req.ticket, 120))
            return error(origin, 409, "ticket_already_used");

        store.remove(MfaKeys.PASSKEY_LOGIN + sid);

// 5. THE WRITE
        // 5. THE WRITE
        store.put(
                MfaKeys.DONE + req.ticket,
                DONE_TTL_SECONDS,
                Map.of(
                        "userId", user.getId(),
                        "rootSessionId", ticket.get("rootSessionId")
                )
        );

// 6. The direct-grant session served its purpose: end it so its tokens stop working.
        try {
            session.sessions().removeUserSession(realm, auth.getSession());
        } catch (RuntimeException e) {
            LOG.warn("could not remove direct-grant session", e);
        }

        return cors(
                origin,
                Response.ok(
                        Map.of("resumeUrl", ticket.get("resumeUrl"))
                )
        ).build();



    }

    // ---- helpers ----

    private static boolean originAllowed(String origin) {
        return origin == null || EnrollmentConfig.loginOrigins().contains(origin);
    }

    private static Response.ResponseBuilder cors(String origin, Response.ResponseBuilder b) {
        if (origin == null) return b;
        return b.header("Access-Control-Allow-Origin", origin)
                .header("Access-Control-Allow-Headers", "Authorization, Content-Type")
                .header("Access-Control-Allow-Methods", "POST, OPTIONS")
                .header("Vary", "Origin");
    }

    private static Response error(String origin, int status, String code) {
        return cors(origin, Response.status(status).entity(Map.of("error", code))
                .type(MediaType.APPLICATION_JSON)).build();
    }
}
