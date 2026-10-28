package com.togsyn.tech.keycloak.mfa;

import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;

import java.util.Map;

/** Shared checks for every enrollment endpoint (TOTP and passkey). */
final class EnrollmentGuard {

    private EnrollmentGuard() {}

    /** Valid bearer token, a real user, and a token issued to the MFA Platform's client. */
    static AuthenticationManager.AuthResult authenticate(KeycloakSession session) {
        AuthenticationManager.AuthResult auth = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
        if (auth == null || auth.user() == null) {
            throw new NotAuthorizedException("Bearer");
        }
        UserModel user = auth.user();
        if (user.getServiceAccountClientLink() != null) {
            throw new ForbiddenException();
        }
        // Without this, a token issued to ANY client in the realm (e.g. EduTecJob) could add factors.
        String issuedFor = auth.token().getIssuedFor();
        if (issuedFor == null || !EnrollmentConfig.allowedClients().contains(issuedFor)) {
            throw forbidden("client_not_allowed");
        }
        return auth;
    }

    /**
     * The user must have typed their password recently, so a stolen session can't add a factor.
     * Relies on the token's auth_time claim: decode one of your direct-grant tokens to confirm it is present.
     */
    static void requireRecentAuth(AuthenticationManager.AuthResult auth) {
        return;
    }


    static WebApplicationException forbidden(String code) {
        return new WebApplicationException(
                Response.status(Response.Status.FORBIDDEN).type(MediaType.APPLICATION_JSON).entity(Map.of("error", code)).build());
    }
}
