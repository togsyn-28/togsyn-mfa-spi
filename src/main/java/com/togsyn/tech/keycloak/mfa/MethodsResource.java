package com.togsyn.tech.keycloak.mfa;

import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.services.managers.AuthenticationManager;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * What the signed-in user has enrolled, read straight from Keycloak's credential store.
 *
 *   GET    /realms/{realm}/mfa-enroll/methods        -> {methods: [{id, type, label, createdDate}]}
 *   DELETE /realms/{realm}/mfa-enroll/methods/{id}   -> 204
 *
 * Why not the Account REST API? It only lists a credential type when an authentication flow in the realm
 * uses it, and its delete endpoint is deprecated and needs an acr claim on the token. This endpoint does
 * not depend on flow configuration, and enforces the same guard as enrollment.
 */
public class MethodsResource {

    /** Only these credential types are exposed or removable here (never the password). */
    private static final Set<String> MANAGED_TYPES =
            Set.of(OTPCredentialModel.TYPE, WebAuthnCredentialModel.TYPE_PASSWORDLESS);

    private final KeycloakSession session;

    public MethodsResource(KeycloakSession session) {
        this.session = session;
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response list() {
        UserModel user = EnrollmentGuard.authenticate(session).user();

        List<Map<String, Object>> methods = MANAGED_TYPES.stream()
                .flatMap(type -> user.credentialManager().getStoredCredentialsByTypeStream(type))
                .map(MethodsResource::toJson)
                .collect(Collectors.toList());

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("methods", methods);
        return cors(Response.ok(body).type(MediaType.APPLICATION_JSON)).build();
    }

    @DELETE
    @Path("{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response remove(@PathParam("id") String id) {
        AuthenticationManager.AuthResult auth = EnrollmentGuard.authenticate(session);
        EnrollmentGuard.requireRecentAuth(auth);
        UserModel user = auth.user();

        CredentialModel credential = user.credentialManager().getStoredCredentialById(id);
        if (credential == null || !MANAGED_TYPES.contains(credential.getType())) {
            return error(Response.Status.NOT_FOUND, "not_found");
        }
        user.credentialManager().removeStoredCredentialById(id);
        // TODO: emit a Keycloak event (EventType.REMOVE_CREDENTIAL) if you need this in the audit log.
        return cors(Response.noContent()).build();
    }

    private static Map<String, Object> toJson(CredentialModel c) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", c.getId());
        m.put("type", c.getType());
        m.put("label", c.getUserLabel());
        m.put("createdDate", c.getCreatedDate());
        return m;
    }

    private static Response error(Response.Status status, String code) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", code);
        return Response.status(status).type(MediaType.APPLICATION_JSON).entity(body).build();
    }
    private Response.ResponseBuilder cors(Response.ResponseBuilder rb) {
        return rb
                .header("Access-Control-Allow-Origin", "http://localhost:5173")
                .header("Access-Control-Allow-Credentials", "true")
                .header("Access-Control-Allow-Headers", "Authorization, Content-Type")
                .header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
    }
    @jakarta.ws.rs.OPTIONS
    public Response options() {
        return cors(Response.ok()).build();
    }
}
