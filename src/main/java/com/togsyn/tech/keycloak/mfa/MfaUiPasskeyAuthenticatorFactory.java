package com.togsyn.tech.keycloak.mfa;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

/**
 * Registers the browser-flow step "MFA UI Passkey", which hands the login to the React MFA Platform UI.
 * Separate from PasskeyDirectGrantAuthenticator (direct grant flow); the two do not interact.
 */
public class MfaUiPasskeyAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "mfa-ui-passkey";
    /** Config key the authenticator reads: ctx.getAuthenticatorConfig().getConfig().get(CONFIG_UI_BASE_URL) */
    public static final String CONFIG_UI_BASE_URL = "mfa.ui.baseUrl";

    // The authenticator keeps no per-request state, so one shared instance is fine.
    private static final MfaUiPasskeyAuthenticator SINGLETON = new MfaUiPasskeyAuthenticator();

    private static final Requirement[] REQUIREMENT_CHOICES = {
            Requirement.ALTERNATIVE,
            Requirement.REQUIRED,
            Requirement.DISABLED
    };

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
            .property()
            .name(CONFIG_UI_BASE_URL)
            .label("MFA UI login URL")
            .helpText("Where the browser is sent to sign in, e.g. http://localhost:5173/login. "
                    + "A one-time 'ticket' query parameter is appended.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .defaultValue("http://localhost:5173/login")
            .add()
            .build();

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "MFA UI Passkey";
    }

    @Override
    public String getReferenceCategory() {
        return WebAuthnCredentialModel.TYPE_PASSWORDLESS;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Redirects the browser to the MFA Platform UI to sign in with a passkey, "
                + "then resumes the Keycloak login when the UI reports success.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}