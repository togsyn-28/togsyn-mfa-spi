package com.togsyn.tech.keycloak.mfa;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.apache.commons.codec.binary.Base32;
import org.jboss.logging.Logger;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.OTPCredentialProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OTPPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.utils.CredentialValidation;
import org.keycloak.models.utils.HmacOTP;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Bearer-authenticated enrollment for the logged-in user.
 *
 * POST /realms/{realm}/mfa-enroll/totp/setup      -> {secret, manualKey, otpauthUri}
 * POST /realms/{realm}/mfa-enroll/totp/verify     -> {enrolled: true}
 * POST /realms/{realm}/mfa-enroll/passkey/options -> WebAuthn creation options   (sub-resource)
 * POST /realms/{realm}/mfa-enroll/passkey/verify  -> {enrolled: true}            (sub-resource)
 * POST /realms/{realm}/mfa-enroll/passkey-login/options -> challenge for "Sign in with passkey" (public)
 * GET  /realms/{realm}/mfa-enroll/methods         -> enrolled TOTP / passkeys     (sub-resource)
 * DELETE /realms/{realm}/mfa-enroll/methods/{id}  -> remove one                  (sub-resource)
 *
 * CHANGES vs the original: (1) authenticate() now goes through EnrollmentGuard (token must be issued
 * to an allowed client); (2) the passkey() sub-resource locator below.
 */
public class TotpEnrollmentResource {

    private static final Logger LOG =
            Logger.getLogger(TotpEnrollmentResource.class);

    private static final int SECRET_LENGTH = 20;
    private static final String CREDENTIAL_LABEL = "Authenticator app";

    private final KeycloakSession session;
    private final String issuer;

    public TotpEnrollmentResource(KeycloakSession session, String issuer) {
        this.session = session;
        this.issuer = issuer;
    }

    // ---- NEW: routes /mfa-enroll/passkey/* to the passkey resource ----
    @Path("passkey")
    public PasskeyEnrollmentResource passkey() {
        return new PasskeyEnrollmentResource(session);
    }

    // ---- NEW: public step 1 of "Sign in with passkey" (/mfa-enroll/passkey-login/options) ----
    @Path("passkey-login")
    public PasskeyLoginResource passkeyLogin() {
        return new PasskeyLoginResource(session);
    }

    // ---- NEW: routes /mfa-enroll/methods to the list/remove resource ----
    @Path("methods")
    public MethodsResource methods() {
        return new MethodsResource(session);
    }

    public static class VerifyRequest {
        public String secret;
        public String code;

    }

    @POST
    @Path("totp/setup")
    @Produces(MediaType.APPLICATION_JSON)
    public Response setup() {
        UserModel user = authenticate();
        RealmModel realm = session.getContext().getRealm();

        if (hasOtp(user)) {
            return error(Response.Status.CONFLICT, "already_enrolled");
        }

        OTPPolicy policy = realm.getOTPPolicy();
        if (!OTPCredentialModel.TOTP.equals(policy.getType())) {
            // Only time-based codes are supported by this flow.
            return error(Response.Status.INTERNAL_SERVER_ERROR, "otp_policy_not_totp");
        }

        String secret = HmacOTP.generateSecret(SECRET_LENGTH);
        Base32 base32 = new Base32();
        String manualKey = new String(
                base32.encode(secret.getBytes(StandardCharsets.UTF_8)),
                StandardCharsets.UTF_8
        ).replace("=", "");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("secret", secret);
        body.put("manualKey", manualKey);
        body.put("otpauthUri", buildOtpAuthUri(policy, user, manualKey));
        return Response.ok(body).type(MediaType.APPLICATION_JSON).build();
    }

    @POST
    @Path("totp/verify")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response verify(VerifyRequest request) {
        System.out.println("SPI SECRET = " + request.secret);
        System.out.println("SPI CODE = " + request.code);
        UserModel user = authenticate();
        RealmModel realm = session.getContext().getRealm();

        if (hasOtp(user)) {
            return error(Response.Status.CONFLICT, "already_enrolled");
        }
        if (request == null || isBlank(request.secret) || isBlank(request.code)) {
            return error(Response.Status.BAD_REQUEST, "invalid_request");
        }

        OTPPolicy policy = realm.getOTPPolicy();
        String secret = request.secret.trim();
        String code = request.code.trim();

        if (secret.length() < SECRET_LENGTH) {
            return error(Response.Status.BAD_REQUEST, "invalid_secret");
        }
        if (!code.matches("\\d{" + policy.getDigits() + "}")) {
            return error(Response.Status.BAD_REQUEST, "invalid_code");
        }
        System.out.println("POLICY DIGITS = " + policy.getDigits());
        System.out.println("LOOKAHEAD = " + policy.getLookAheadWindow());

        OTPCredentialModel credential =
                OTPCredentialModel.createFromPolicy(
                        realm,
                        secret,
                        CREDENTIAL_LABEL
                );        boolean ok = CredentialValidation.validOTP(code, credential, 10);
        if (!ok) {
            boolean wide = CredentialValidation.validOTP(code, credential, 10);   // diagnostic only
            LOG.warnf("TOTP rejected: serverTime=%s alg=%s digits=%d period=%d lookAhead=%d passesWithWindow10=%s",
                    Instant.now(), policy.getAlgorithm(), policy.getDigits(),
                    policy.getPeriod(), policy.getLookAheadWindow(), wide);
            return error(Response.Status.BAD_REQUEST, "invalid_code");
        }

        OTPCredentialProvider provider = (OTPCredentialProvider) session.getProvider(CredentialProvider.class, "keycloak-otp");
        provider.createCredential(realm, user, credential);

        user.removeRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("enrolled", true);
        return Response.ok(body).type(MediaType.APPLICATION_JSON).build();
    }

    /**
     * Valid bearer token + token issued to an allowed client (see MFA_ALLOWED_CLIENTS).
     * TODO: also call EnrollmentGuard.requireRecentAuth(auth) here once the TOTP drawer asks for the
     * password again (the passkey drawer already does). Until then TOTP is not gated on a recent login.
     */
    private UserModel authenticate() {
        return EnrollmentGuard.authenticate(session).user();
    }

    private boolean hasOtp(UserModel user) {
        return user.credentialManager()
                .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
                .findAny()
                .isPresent();
    }

    private String buildOtpAuthUri(OTPPolicy policy, UserModel user, String base32Secret) {
        String label = user.getEmail() != null ? user.getEmail() : user.getUsername();
        // "HmacSHA1" -> "SHA1" as the otpauth:// spec expects.
        String algorithm = policy.getAlgorithm().replace("Hmac", "");
        return "otpauth://totp/" + enc(issuer) + ":" + enc(label)
                + "?secret=" + base32Secret
                + "&issuer=" + enc(issuer)
                + "&algorithm=" + algorithm
                + "&digits=" + policy.getDigits()
                + "&period=" + policy.getPeriod();
    }

    private static String enc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    private static Response error(Response.Status status, String code) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", code);
        return Response.status(status).type(MediaType.APPLICATION_JSON).entity(body).build();
    }
}
