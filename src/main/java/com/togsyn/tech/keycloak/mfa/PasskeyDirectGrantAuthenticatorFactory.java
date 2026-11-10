package com.togsyn.tech.keycloak.mfa;

import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class PasskeyDirectGrantAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "mfa-passkey-direct-grant";
    static final String BUILD = "v3-2026-11-07";   // change on every build

    private static final PasskeyDirectGrantAuthenticator INSTANCE = new PasskeyDirectGrantAuthenticator();

    @Override
    public void init(Config.Scope config) {
        System.out.println("[PASSKEY] FACTORY.init build=" + BUILD);       // runs once at startup
    }

    @Override public void postInit(KeycloakSessionFactory f) { }
    @Override public void close() { }

    @Override
    public Authenticator create(KeycloakSession session) {
        System.out.println("[PASSKEY] FACTORY.create build=" + BUILD + " id=" + PROVIDER_ID);
        return INSTANCE;
    }

    @Override public String getId() { return PROVIDER_ID; }
    @Override public String getDisplayType() { return "MFA Passkey Direct Grant"; }
    @Override public String getReferenceCategory() { return "passkey"; }
    @Override public boolean isConfigurable() { return false; }
    @Override public boolean isUserSetupAllowed() { return false; }

    @Override
    public Requirement[] getRequirementChoices() {
        return new Requirement[] { Requirement.ALTERNATIVE, Requirement.DISABLED };
    }

    @Override public String getHelpText() { return "Usernameless passkey login for the direct grant"; }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return List.of(); }
}