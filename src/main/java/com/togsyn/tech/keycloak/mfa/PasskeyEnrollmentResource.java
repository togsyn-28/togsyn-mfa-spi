package com.togsyn.tech.keycloak.mfa;

import com.webauthn4j.WebAuthnRegistrationManager;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Base64Url;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.WebAuthnCredentialModelInput;
import org.keycloak.credential.WebAuthnCredentialProvider;
import org.keycloak.credential.WebAuthnPasswordlessCredentialProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.WebAuthnPolicy;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.util.JsonSerialization;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * In-app passkey registration, driven by the MFA Platform UI (no Keycloak pages).
 *
 *   POST /realms/{realm}/mfa-enroll/passkey/options -> WebAuthn creation options (JSON)
 *   POST /realms/{realm}/mfa-enroll/passkey/verify  -> {enrolled: true}
 *
 * Follows Keycloak's own WebAuthnRegister required action (services module), including how it
 * builds the credential, so the stored credential is a normal "webauthn-passwordless" one.
 *
 * Written against Keycloak 26.0.x APIs. Differences on newer versions are listed at the bottom.
 */
public class PasskeyEnrollmentResource {

    private static final Logger LOG = Logger.getLogger(PasskeyEnrollmentResource.class);
    private static final int CHALLENGE_BYTES = 32;
    private static final int CHALLENGE_TTL_SECONDS = 120;
    private static final String CHALLENGE_KEY_PREFIX = "mfa-passkey:";
    private static final String DEFAULT_LABEL = "Passkey";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final KeycloakSession session;

    public PasskeyEnrollmentResource(KeycloakSession session) {
        this.session = session;
    }

    public static class VerifyRequest {
        public String id;
        public String rawId;
        public String type;
        public String label;
        public AttestationResponse response;

        public static class AttestationResponse {
            public String clientDataJSON;
            public String attestationObject;
            public List<String> transports;
        }
    }

    // ============================================================== options

    @POST
    @Path("options")
    @Produces(MediaType.APPLICATION_JSON)
    public Response options() {
        AuthenticationManager.AuthResult auth = EnrollmentGuard.authenticate(session);
        EnrollmentGuard.requireRecentAuth(auth);
        UserModel user = auth.user();
        WebAuthnPolicy policy = realm().getWebAuthnPolicyPasswordless();

        byte[] challengeBytes = new byte[CHALLENGE_BYTES];
        RANDOM.nextBytes(challengeBytes);
        String challenge = Base64Url.encode(challengeBytes);
        // Single-use and short-lived; also works across Keycloak cluster nodes.
        session.singleUseObjects().put(challengeKey(user, challenge), CHALLENGE_TTL_SECONDS, Map.of("userId", user.getId()));

        Map<String, Object> rp = new LinkedHashMap<>();
        rp.put("name", policy.getRpEntityName());
        rp.put("id", rpId(policy));

        // Same encoding as Keycloak's own page: the user id as UTF-8 bytes. Passkey login relies on it.
        String userHandle = Base64Url.encode(user.getId().getBytes(StandardCharsets.UTF_8));
        String name = user.getEmail() != null ? user.getEmail() : user.getUsername();
        String fullName = ((user.getFirstName() == null ? "" : user.getFirstName()) + " "
                + (user.getLastName() == null ? "" : user.getLastName())).trim();
        Map<String, Object> userJson = new LinkedHashMap<>();
        userJson.put("id", userHandle);
        userJson.put("name", name);
        userJson.put("displayName", fullName.isEmpty() ? name : fullName);

        Map<String, Object> selection = new LinkedHashMap<>();
        putIfSet(selection, "authenticatorAttachment", policy.getAuthenticatorAttachment());
        putIfSet(selection, "userVerification", policy.getUserVerificationRequirement());
        String resident = policy.getRequireResidentKey();
        if ("Yes".equalsIgnoreCase(resident)) {
            selection.put("residentKey", "required");
            selection.put("requireResidentKey", true);
        } else if ("No".equalsIgnoreCase(resident)) {
            selection.put("residentKey", "discouraged");
            selection.put("requireResidentKey", false);
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("challenge", challenge);
        body.put("rp", rp);
        body.put("user", userJson);
        body.put("pubKeyCredParams", pubKeyCredParams(policy));
        if (policy.getCreateTimeout() > 0) body.put("timeout", policy.getCreateTimeout() * 1000);
        body.put("excludeCredentials", policy.isAvoidSameAuthenticatorRegister() ? excludeList(user) : List.of());
        body.put("authenticatorSelection", selection);
        putIfSet(body, "attestation", policy.getAttestationConveyancePreference());
        return cors(Response.ok(body).type(MediaType.APPLICATION_JSON)).build();
    }

    // =============================================================== verify

    @POST
    @Path("verify")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response verify(VerifyRequest request) {
        AuthenticationManager.AuthResult auth = EnrollmentGuard.authenticate(session);
        EnrollmentGuard.requireRecentAuth(auth);
        UserModel user = auth.user();
        RealmModel realm = realm();
        WebAuthnPolicy policy = realm.getWebAuthnPolicyPasswordless();

        if (request == null || request.response == null || isBlank(request.response.clientDataJSON)
                || isBlank(request.response.attestationObject)) {
            return error(Response.Status.BAD_REQUEST, "invalid_request");
        }

        byte[] clientDataBytes;
        byte[] attestationBytes;
        Map<?, ?> clientData;
        try {
            clientDataBytes = Base64Url.decode(request.response.clientDataJSON);
            attestationBytes = Base64Url.decode(request.response.attestationObject);
            clientData = JsonSerialization.readValue(clientDataBytes, Map.class);
        } catch (Exception e) {
            return error(Response.Status.BAD_REQUEST, "invalid_request");
        }

        String challenge = String.valueOf(clientData.get("challenge"));
        String origin = String.valueOf(clientData.get("origin"));

        if (!"webauthn.create".equals(clientData.get("type"))) {
            return error(Response.Status.BAD_REQUEST, "invalid_request");
        }
        // Must be a challenge we issued to THIS user; consuming it makes it single-use.
        if (session.singleUseObjects().remove(challengeKey(user, challenge)) == null) {
            return error(Response.Status.BAD_REQUEST, "invalid_challenge");
        }
        // Only the MFA Platform's own origin may register passkeys through this endpoint.
        if (!EnrollmentConfig.platformOrigins().contains(origin)) {
            return error(Response.Status.BAD_REQUEST, "invalid_origin");
        }

        RegistrationData data;
        try {
            data = validateAttestation(policy, request, clientDataBytes, attestationBytes, challenge, origin);
        } catch (Exception e) {
            // Logged so you can see WHY in `docker logs keycloak` (the response only says invalid_attestation).
            LOG.warn("Passkey attestation validation failed", e);
            return error(Response.Status.BAD_REQUEST, "invalid_attestation");
        }

        Map<String, Object> body = new LinkedHashMap<>();
        if (EnrollmentConfig.passkeyDryRun()) {
            // STAGE 3 TEST: everything was checked, nothing is stored.
            body.put("enrolled", false);
            body.put("dryRun", true);
            return Response.ok(body).type(MediaType.APPLICATION_JSON).build();
        }

        try {
            store(realm, user, data, request.label);
        } catch (ModelDuplicateException e) {
            return error(Response.Status.CONFLICT, "duplicate_credential");
        } catch (Exception e) {
            LOG.error("Storing the passkey credential failed", e);
            return error(Response.Status.INTERNAL_SERVER_ERROR, "store_failed");
        }
        body.put("enrolled", true);
        return cors(Response.ok(body).type(MediaType.APPLICATION_JSON)).build();
    }

    /** Checks signature, challenge, origin, rpId and user verification with webauthn4j (same as Keycloak does). */
    private RegistrationData validateAttestation(WebAuthnPolicy policy, VerifyRequest request, byte[] clientDataBytes,
                                                 byte[] attestationBytes, String challenge, String origin) {
        Set<String> transports = request.response.transports == null || request.response.transports.isEmpty()
                ? null : new HashSet<>(request.response.transports);
        RegistrationRequest registrationRequest = transports == null
                ? new RegistrationRequest(attestationBytes, clientDataBytes)
                : new RegistrationRequest(attestationBytes, clientDataBytes, transports);

        // VERSION: 26.0.x uses a single Origin: new ServerProperty(new Origin(origin), rpId, challenge, null)
        //          26.1.x and later take a Set of origins (this line).
        ServerProperty serverProperty = new ServerProperty(
                Set.of(new Origin(origin)), rpId(policy), new DefaultChallenge(Base64Url.decode(challenge)), null);
        // Don't trust the browser's word that verification happened: require it ourselves.
        boolean userVerificationRequired = "required".equals(policy.getUserVerificationRequirement());
        // VERSION: 26.0.x - 26.5.x use new RegistrationParameters(serverProperty, userVerificationRequired);
        //          26.6.x also takes the expected credential parameters (this line).
        List<PublicKeyCredentialParameters> expectedParams = coseAlgorithms(policy).stream()
                .map(alg -> new PublicKeyCredentialParameters(
                        PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.create(alg.longValue())))
                .toList();
        RegistrationParameters parameters = new RegistrationParameters(serverProperty, expectedParams, userVerificationRequired);

        // Non-strict: accepts "none" and self attestation and does not trust-check attestation certificates.
        // That is right for attestation "none" (the default). Use Keycloak's strict manager if you require
        // attestation from specific hardware vendors.
        WebAuthnRegistrationManager manager = WebAuthnRegistrationManager.createNonStrictWebAuthnRegistrationManager();
        RegistrationData data = manager.parse(registrationRequest);
        // VERSION: 26.0.x to 26.2.x call manager.validate(...); 26.3.x and later call manager.verify(...).
        manager.verify(data, parameters);
        return data;
    }

    /** Writes the credential exactly the way Keycloak's WebAuthnRegister does. */
    private void store(RealmModel realm, UserModel user, RegistrationData data, String label) {
        AttestationObject attestationObject = data.getAttestationObject();
        AuthenticatorData<?> authenticatorData = attestationObject.getAuthenticatorData();
        AttestedCredentialData attestedCredentialData = authenticatorData.getAttestedCredentialData();
        if (attestedCredentialData == null) {
            throw new IllegalStateException("No attested credential data in the response");
        }

        WebAuthnCredentialModelInput credential = new WebAuthnCredentialModelInput(WebAuthnCredentialModel.TYPE_PASSWORDLESS);
        credential.setAttestedCredentialData(attestedCredentialData);
        credential.setCount(authenticatorData.getSignCount());
        credential.setAttestationStatementFormat(attestationObject.getFormat());
        credential.setTransports(data.getTransports());

        WebAuthnCredentialProvider provider = (WebAuthnCredentialProvider) session.getProvider(
                CredentialProvider.class, WebAuthnPasswordlessCredentialProviderFactory.PROVIDER_ID);
        String safeLabel = isBlank(label) ? DEFAULT_LABEL : label.trim();
        WebAuthnCredentialModel model = provider.getCredentialModelFromCredentialInput(credential, safeLabel);
        provider.createCredential(realm, user, model);
    }

    // ============================================================== helpers

    private RealmModel realm() {
        return session.getContext().getRealm();
    }

    private static String challengeKey(UserModel user, String challenge) {
        return CHALLENGE_KEY_PREFIX + user.getId() + ":" + challenge;
    }

    /** Realm policy rpId, or the Keycloak host when empty (identical to Keycloak's own page). */
    private String rpId(WebAuthnPolicy policy) {
        String configured = policy.getRpId();
        return configured != null && !configured.isEmpty() ? configured : session.getContext().getUri().getBaseUri().getHost();
    }

    /** COSE algorithm ids for the realm's allowed signature algorithms (defaults to ES256, RS256). */
    private static List<Integer> coseAlgorithms(WebAuthnPolicy policy) {
        List<String> names = policy.getSignatureAlgorithm();
        List<Integer> out = new ArrayList<>();
        if (names != null) {
            for (String name : names) {
                Integer cose = switch (name) {
                    case "ES256" -> -7;
                    case "ES384" -> -35;
                    case "ES512" -> -36;
                    case "RS256" -> -257;
                    case "RS384" -> -258;
                    case "RS512" -> -259;
                    case "Ed25519" -> -8;
                    case "RS1" -> -65535;
                    default -> null;
                };
                if (cose != null) out.add(cose);
            }
        }
        if (out.isEmpty()) {
            out.add(-7);
            out.add(-257);
        }
        return out;
    }

    private static List<Map<String, Object>> pubKeyCredParams(WebAuthnPolicy policy) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Integer cose : coseAlgorithms(policy)) {
            Map<String, Object> p = new LinkedHashMap<>();
            p.put("type", "public-key");
            p.put("alg", cose);
            out.add(p);
        }
        return out;
    }

    /** Existing passkeys, so the same authenticator isn't registered twice (same logic as Keycloak). */
    private static List<Map<String, Object>> excludeList(UserModel user) {
        return user.credentialManager().getStoredCredentialsByTypeStream(WebAuthnCredentialModel.TYPE_PASSWORDLESS)
                .map(c -> {
                    WebAuthnCredentialModel m = WebAuthnCredentialModel.createFromCredentialModel(c);
                    Map<String, Object> e = new LinkedHashMap<>();
                    e.put("type", "public-key");
                    e.put("id", Base64Url.encodeBase64ToBase64Url(m.getWebAuthnCredentialData().getCredentialId()));
                    return e;
                })
                .collect(Collectors.toList());
    }

    private static void putIfSet(Map<String, Object> target, String key, String value) {
        if (value != null && !value.isBlank() && !"not specified".equalsIgnoreCase(value)) target.put(key, value);
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
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
                .header("Access-Control-Allow-Methods", "POST, OPTIONS");
    }
    @jakarta.ws.rs.OPTIONS
    @Path("options")
    public Response optionsPreflight() {
        return cors(Response.ok()).build();
    }
    @jakarta.ws.rs.OPTIONS
    @Path("verify")
    public Response verifyPreflight() {
        return cors(Response.ok()).build();
    }

    /*
     * Checked against the Keycloak source for 26.0.8, 26.1.5, 26.2.5, 26.3.5, 26.4.0, 26.4.7, 26.5.0 and 26.6.3.
     * Lines that differ between 26.x releases are marked "VERSION" above:
     *
     *   Keycloak          ServerProperty first arg      manager call   RegistrationParameters
     *   26.0.x            new Origin(origin)            validate       (serverProperty, uvRequired)
     *   26.1.x - 26.2.x   Set.of(new Origin(origin))    validate       (serverProperty, uvRequired)
     *   26.3.x - 26.5.x   Set.of(new Origin(origin))    verify         (serverProperty, uvRequired)
     *   26.6.x            Set.of(new Origin(origin))    verify         (serverProperty, expectedParams, uvRequired)  <- as written
     *
     * Also in 26.5+: AuthenticationManager.AuthResult is a record, so use auth.user() / auth.token()
     * instead of the deprecated getUser() / getToken(), and IDToken exposes getAuth_time() (not getAuthTime()).
     */

}
