package com.togsyn.tech.keycloak.mfa;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class DirectGrantOtpAuthenticatorFactory implements AuthenticatorFactory {
    public static final String ID = "direct-grant-togsyn-otp";
    private static final AuthenticationExecutionModel.Requirement[] REQ =
            { AuthenticationExecutionModel.Requirement.REQUIRED };

    @Override public String getId() { return ID; }
    @Override public String getDisplayType() { return "Direct Grant - Require OTP (Togsyn)"; }
    @Override public String getReferenceCategory() { return "otp"; }
    @Override public boolean isConfigurable() { return false; }
    @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices() { return REQ; }
    @Override public boolean isUserSetupAllowed() { return false; }
    @Override public String getHelpText() { return "Requires the totp form parameter when the user has an OTP credential."; }
    @Override public java.util.List<org.keycloak.provider.ProviderConfigProperty> getConfigProperties() { return java.util.List.of(); }
    @Override public Authenticator create(KeycloakSession session) { return new DirectGrantOtpAuthenticator(); }
    @Override public void init(org.keycloak.Config.Scope config) {}
    @Override public void postInit(KeycloakSessionFactory factory) {}
    @Override public void close() {}
}
