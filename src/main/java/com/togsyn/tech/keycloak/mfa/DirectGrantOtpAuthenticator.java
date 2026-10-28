package com.togsyn.tech.keycloak.mfa;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.*;
import org.keycloak.events.Errors;
import org.keycloak.models.*;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.utils.CredentialValidation;

import java.util.Map;

public class DirectGrantOtpAuthenticator implements Authenticator {


    @Override
    public void authenticate(AuthenticationFlowContext ctx) {
        UserModel user = ctx.getUser();
        RealmModel realm = ctx.getRealm();

        if (user == null) {
            ctx.failure(AuthenticationFlowError.UNKNOWN_USER);
            return;
        }

        if (!user.credentialManager().isConfiguredFor(OTPCredentialModel.TYPE)) {
            ctx.success();
            return;
        }

        String totp = ctx.getHttpRequest().getDecodedFormParameters().getFirst("totp");
        if (totp == null || totp.isBlank()) {
            // Password was correct; tell the UI to ask for the code. Not counted as a failed login.
            ctx.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
                    reject("otp_required", "One-time code required"));
            return;
        }
        String code = totp.trim();

        user.credentialManager()
                .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
                .forEach(cm -> {
                    OTPCredentialModel c =
                            OTPCredentialModel.createFromCredentialModel(cm);

                    int smallest = -1;

                    for (int n = 0; n <= 60; n++) {
                        if (CredentialValidation.validOTP(code, c, n)) {
                            smallest = n;
                            break;
                        }
                    }


                });

        if (!code.matches("\\d{6}") || !validOtp(ctx.getRealm(), user, code)) {
            ctx.getEvent().user(user).error(Errors.INVALID_USER_CREDENTIALS);
            ctx.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
                    reject("invalid_otp", "Invalid one-time code"));
            return;
        }
        ctx.success();
    }

    private static Response reject(String error, String description) {
        return Response.status(Response.Status.UNAUTHORIZED).type(MediaType.APPLICATION_JSON)
                .entity(Map.of("error", error, "error_description", description)).build();
    }

    private static boolean validOtp(RealmModel realm, UserModel user, String code) {
        OTPPolicy policy = realm.getOTPPolicy();
        return user.credentialManager()
                .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
                .map(OTPCredentialModel::createFromCredentialModel)
                .anyMatch(c -> CredentialValidation.validOTP(code, c, policy.getLookAheadWindow()));
    }

    @Override public void action(AuthenticationFlowContext ctx) {}
    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(KeycloakSession s, RealmModel r, UserModel u) { return true; }
    @Override public void setRequiredActions(KeycloakSession s, RealmModel r, UserModel u) {}
    @Override public void close() {}
}