package com.togsyn.tech.keycloak.mfa;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import java.util.ArrayList;
import java.util.List;

/**
 * Adds two claims, computed live from the user's stored credentials:
 *   mfa_enrolled : boolean, true when the user has a TOTP or a passkey
 *   mfa_methods  : e.g. ["totp", "passkey"]
 * Informational only (for UX). Enforce MFA with the authentication flow and the acr claim.
 * Values are fixed when a token is issued, so they lag until the next token refresh.
 */
public class MfaEnrolledMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    public static final String PROVIDER_ID = "togsyn-mfa-enrolled-mapper";
    public static final String CLAIM_ENROLLED = "mfa_enrolled";
    public static final String CLAIM_METHODS = "mfa_methods";

    // Keycloak's credential type for passkeys (WebAuthn passwordless).
    private static final String TYPE_PASSKEY = "webauthn-passwordless";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(CONFIG_PROPERTIES, MfaEnrolledMapper.class);
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Togsyn MFA Enrolled";
    }

    @Override
    public String getHelpText() {
        return "Adds 'mfa_enrolled' (true when the user has a TOTP or passkey) and 'mfa_methods'.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession,
                            KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        UserModel user = userSession.getUser();
        List<String> methods = new ArrayList<>();
        if (has(user, OTPCredentialModel.TYPE)) methods.add("totp");
        if (has(user, TYPE_PASSKEY)) methods.add("passkey");

        token.getOtherClaims().put(CLAIM_ENROLLED, !methods.isEmpty());
        token.getOtherClaims().put(CLAIM_METHODS, methods);
    }

    private static boolean has(UserModel user, String credentialType) {
        return user.credentialManager()
                .getStoredCredentialsByTypeStream(credentialType)
                .findAny()
                .isPresent();
    }
}
