package com.togsyn.tech.keycloak.mfa;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class MfaLoginResourceProviderFactory implements RealmResourceProviderFactory {
    public static final String ID = "mfa-login";

    @Override public String getId() { return ID; }

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new RealmResourceProvider() {
            @Override public Object getResource() { return new MfaLoginResource(session); }
            @Override public void close() {}
        };
    }

    @Override public void init(Config.Scope config) {}
    @Override public void postInit(KeycloakSessionFactory factory) {}
    @Override public void close() {}
}