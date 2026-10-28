package com.togsyn.tech.keycloak.mfa;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class TotpEnrollmentResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;
    private final String issuer;

    public TotpEnrollmentResourceProvider(KeycloakSession session, String issuer) {
        this.session = session;
        this.issuer = issuer;
    }

    @Override
    public Object getResource() {
        return new TotpEnrollmentResource(session, issuer);
    }

    @Override
    public void close() {
    }
}