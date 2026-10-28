package com.togsyn.tech.keycloak.mfa;

import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.exception.WebAuthnException;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.directgrant.AbstractDirectGrantAuthenticator;
import org.keycloak.authentication.authenticators.util.AuthenticatorUtils;
import org.keycloak.common.util.Base64Url;
import org.keycloak.credential.WebAuthnCredentialModelInput;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.WebAuthnPolicy;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.util.JsonSerialization;

import java.nio.charset.StandardCharsets;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * Direct Grant step that signs a user in with a passkey, so the MFA Platform can stay in its own UI.
 *
 * The client calls the normal token endpoint:
 *   POST /realms/{realm}/protocol/openid-connect/token
 *   grant_type=password & client_id=web-app & passkey_assertion=<JSON from navigator.credentials.get()>
 *
 * Put this step FIRST in the direct grant flow as ALTERNATIVE, followed by the password sub-flow as ALTERNATIVE.
 * No passkey_assertion parameter -> this step steps aside (attempted) and the password sub-flow runs as before.
 *
 * Verification mirrors Keycloak's own WebAuthnAuthenticator.action(): the user is found from the passkey's
 * user handle (the user id, encoded when the passkey was registered), then Keycloak's WebAuthn credential
 * provider checks the signature and updates the signature counter. This class is both the authenticator and
 * its factory, like Keycloak's built-in direct grant steps.
 */
public class PasskeyDirectGrantAuthenticator extends AbstractDirectGrantAuthenticator {

    public static final String PROVIDER_ID = "mfa-passkey-direct-grant";
    public static final String PARAM_ASSERTION = "passkey_assertion";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> params = context.getHttpRequest().getDecodedFormParameters();
        String raw = params.getFirst(PARAM_ASSERTION);
        if (raw == null || raw.isBlank()) {
            context.attempted(); // not a passkey login: let the password sub-flow handle it
            return;
        }

        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        context.getEvent().detail(Details.CREDENTIAL_TYPE, WebAuthnCredentialModel.TYPE_PASSWORDLESS);

        byte[] credentialId;
        byte[] clientDataJson;
        byte[] authenticatorData;
        byte[] signature;
        String userHandle;
        Map<?, ?> clientData;
        try {
            Map<?, ?> assertion = JsonSerialization.readValue(raw, Map.class);
            Map<?, ?> response = (Map<?, ?>) assertion.get("response");
            credentialId = Base64Url.decode(str(assertion, "rawId"));
            clientDataJson = Base64Url.decode(str(response, "clientDataJSON"));
            authenticatorData = Base64Url.decode(str(response, "authenticatorData"));
            signature = Base64Url.decode(str(response, "signature"));
            userHandle = str(response, "userHandle");
            clientData = JsonSerialization.readValue(clientDataJson, Map.class);
        } catch (Exception e) {
            fail(context, null, "malformed_assertion");
            return;
        }

        if (!"webauthn.get".equals(clientData.get("type"))) {
            fail(context, null, "wrong_ceremony_type");
            return;
        }
        String challenge = String.valueOf(clientData.get("challenge"));
        String origin = String.valueOf(clientData.get("origin"));

        // The challenge must be one we issued, and it works only once.
        System.out.println("VERIFY CHALLENGE = " + challenge);

        Object existing = session.singleUseObjects().get(
                PasskeyLoginResource.CHALLENGE_KEY_PREFIX + challenge);

        System.out.println(
                "CHALLENGE EXISTS BEFORE REMOVE = " +
                        (existing != null)
        );

        Object removed = session.singleUseObjects().remove(
                PasskeyLoginResource.CHALLENGE_KEY_PREFIX + challenge);

        System.out.println(
                "REMOVE RESULT = " +
                        (removed != null)
        );

        if (removed == null) {
            fail(context, null, "unknown_or_used_challenge");
            return;
        }
        // Only the platform's own origin and the configured client-app origins may use this login path.
        if (!EnrollmentConfig.loginOrigins().contains(origin)) {
            fail(context, null, "origin_not_allowed");
            return;
        }
        if (userHandle == null || userHandle.isBlank()) {
            fail(context, null, "no_user_handle");
            return;
        }

        // Same decoding as Keycloak: the user handle is the user id as UTF-8 bytes.
        String userId = new String(Base64Url.decode(userHandle), StandardCharsets.UTF_8);
        UserModel user = session.users().getUserById(realm, userId);
        if (user == null || user.getServiceAccountClientLink() != null) {
            fail(context, null, "user_not_found");
            return;
        }

        String bruteForceError = AuthenticatorUtils.getDisabledByBruteForceEventError(context, user);
        if (bruteForceError != null) {
            context.getEvent().user(user);
            context.getEvent().error(bruteForceError);
            context.forceChallenge(errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "invalid_grant", "Invalid passkey"));
            return;
        }
        if (!user.isEnabled()) {
            context.getEvent().user(user);
            context.getEvent().error(Errors.USER_DISABLED);
            context.forceChallenge(errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "invalid_grant", "Invalid passkey"));
            return;
        }

        WebAuthnPolicy policy = realm.getWebAuthnPolicyPasswordless();
        String configuredRpId = policy.getRpId();
        String rpId = configuredRpId != null && !configuredRpId.isEmpty()
                ? configuredRpId : context.getUriInfo().getBaseUri().getHost();
        boolean userVerificationRequired = "required".equals(policy.getUserVerificationRequirement());

        ServerProperty server = new ServerProperty(new Origin(origin), rpId, new DefaultChallenge(Base64Url.decode(challenge)), null);

        WebAuthnCredentialModelInput credential = new WebAuthnCredentialModelInput(WebAuthnCredentialModel.TYPE_PASSWORDLESS);
        credential.setAuthenticationRequest(new AuthenticationRequest(credentialId, authenticatorData, clientDataJson, signature));
        credential.setAuthenticationParameters(
                new WebAuthnCredentialModelInput.KeycloakWebAuthnAuthenticationParameters(server, userVerificationRequired));
        // TEMP DIAGNOSTIC - remove after testing
        try {
            boolean idStored = user.credentialManager()
                    .getStoredCredentialsByTypeStream(WebAuthnCredentialModel.TYPE_PASSWORDLESS)
                    .anyMatch(c -> java.util.Arrays.equals(
                            WebAuthnCredentialModel.createFromCredentialModel(c)
                                    .getWebAuthnCredentialData().getCredentialId().getBytes(),
                            credentialId));

            byte[] expectedHash = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(rpId.getBytes(StandardCharsets.UTF_8));

            boolean rpHashOk = authenticatorData.length >= 37
                    && java.util.Arrays.equals(
                    java.util.Arrays.copyOf(authenticatorData, 32),
                    expectedHash
            );

            int flags = authenticatorData.length >= 37
                    ? (authenticatorData[32] & 0xff)
                    : -1;

            System.out.println(
                    "PASSKEY DIAG origin=" + origin
                            + " rpId=" + rpId
                            + " credentialIdStoredForUser=" + idStored
                            + " rpIdHashMatches=" + rpHashOk
                            + " uvRequired=" + userVerificationRequired
                            + " flags=0x" + Integer.toHexString(flags)
            );

        } catch (Exception ex) {
            System.out.println("PASSKEY DIAG failed: " + ex);
        }

        boolean valid;
        try {
            valid = user.credentialManager().isValid(credential);
        } catch (WebAuthnException e) {
            fail(context, user, "verification_failed");
            return;
        }
        if (!valid) {
            fail(context, user, "credential_not_valid");
            return;
        }
        session.singleUseObjects().put(MfaKeys.PASSKEY_LOGIN+context.getAuthenticationSession().getParentSession().getId(),120, Map.of("userId", user.getId()));
        context.setUser(user);
        context.getAuthenticationSession().setAuthNote("togsyn.auth", "passkey");
        context.success(WebAuthnCredentialModel.TYPE_PASSWORDLESS);
    }

    /** One generic answer for every failure, so the response never reveals whether an account exists. */
    private void fail(AuthenticationFlowContext context, UserModel user, String reason) {
        if (user != null) context.getEvent().user(user);
        context.getEvent().detail(Details.REASON, reason);
        context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
        context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
                errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "invalid_grant", "Invalid passkey"));
    }

    private static String str(Map<?, ?> map, String key) {
        Object v = map.get(key);
        return v == null ? null : String.valueOf(v);
    }

    // ---- Authenticator / factory plumbing (same shape as Keycloak's built-in direct grant steps) ----

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getDisplayType() {
        return "MFA Passkey Direct Grant";
    }

    @Override
    public String getReferenceCategory() {
        return WebAuthnCredentialModel.TYPE_PASSWORDLESS;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getHelpText() {
        return "Signs the user in with a passkey sent as the 'passkey_assertion' form parameter. Steps aside when it is absent.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return new LinkedList<>();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
