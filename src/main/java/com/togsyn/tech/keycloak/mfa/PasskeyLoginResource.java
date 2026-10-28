package com.togsyn.tech.keycloak.mfa;

import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.common.util.Base64Url;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.WebAuthnPolicy;

import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Step 1 of "Sign in with passkey" (public endpoint, nobody is logged in yet).
 *
 *   POST /realms/{realm}/mfa-enroll/passkey-login/options -> {challenge, rpId, timeout, userVerification, allowCredentials}
 *
 * The browser asks the user's device to sign the challenge, then sends the result to Keycloak's normal token
 * endpoint, where PasskeyDirectGrantAuthenticator verifies it. The challenge is single-use and short-lived.
 * Because this endpoint is public, rate-limit it at your reverse proxy in production.
 */
public class PasskeyLoginResource {

    /** Shared with PasskeyDirectGrantAuthenticator, which consumes the challenge. */
    static final String CHALLENGE_KEY_PREFIX = "mfa-passkey-login:";

    private static final int CHALLENGE_BYTES = 32;
    private static final int CHALLENGE_TTL_SECONDS = 60;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final KeycloakSession session;

    public PasskeyLoginResource(KeycloakSession session) {
        this.session = session;
    }

    @POST
    @Path("options")
    @Produces(MediaType.APPLICATION_JSON)
    public Response options() {
        WebAuthnPolicy policy = session.getContext().getRealm().getWebAuthnPolicyPasswordless();

        byte[] bytes = new byte[CHALLENGE_BYTES];
        RANDOM.nextBytes(bytes);
        String challenge = Base64Url.encode(bytes);
        System.out.println("GENERATED CHALLENGE = " + challenge);
        session.singleUseObjects().put(CHALLENGE_KEY_PREFIX + challenge, CHALLENGE_TTL_SECONDS, Map.of("purpose", "passkey-login"));

        String rpId = policy.getRpId();
        if (rpId == null || rpId.isEmpty()) {
            rpId = session.getContext().getUri().getBaseUri().getHost();
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("challenge", challenge);
        body.put("rpId", rpId);
        body.put("timeout", policy.getCreateTimeout() > 0 ? policy.getCreateTimeout() * 1000 : 60000);
        String uv = policy.getUserVerificationRequirement();
        if (uv != null && !uv.isBlank() && !"not specified".equalsIgnoreCase(uv)) {
            body.put("userVerification", uv);
        }
        // Empty on purpose: the device offers whichever passkeys it holds for this site (discoverable credentials).
        body.put("allowCredentials", List.of());

        Response.ResponseBuilder response = Response.ok(body).type(MediaType.APPLICATION_JSON);
        // Browser apps on another origin (EduTecJob) may read this answer, but only the configured ones.
        // The request has no body and no custom headers, so the browser sends no preflight.
        String origin = session.getContext().getHttpRequest().getHttpHeaders().getHeaderString("Origin");
        if (origin != null && EnrollmentConfig.loginOrigins().contains(origin)) {
            response.header("Access-Control-Allow-Origin", origin).header("Vary", "Origin");
        }
        return response.build();
    }
}
