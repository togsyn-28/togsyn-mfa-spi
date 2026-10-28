package com.togsyn.tech.keycloak.mfa;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Registers the in-app TOTP enrollment endpoints under
 * /realms/{realm}/mfa-enroll/...
 */
public class TotpEnrollmentResourceProviderFactory implements RealmResourceProviderFactory {

    public static final String ID = "mfa-enroll";
    private static final String DEFAULT_ISSUER = "Togsyn MFA";

    private String issuer = DEFAULT_ISSUER;

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new TotpEnrollmentResourceProvider(session, issuer);
    }

    @Override
    public void init(Config.Scope config) {
        // Name shown in the authenticator app next to the account label.
        this.issuer = config.get("issuer", DEFAULT_ISSUER);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}