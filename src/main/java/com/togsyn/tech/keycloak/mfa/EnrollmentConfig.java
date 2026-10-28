package com.togsyn.tech.keycloak.mfa;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

/** Settings read from environment variables on the Keycloak server. */
final class EnrollmentConfig {

    private EnrollmentConfig() {}

    /** Clients whose tokens may enroll factors (the MFA Platform's client). MFA_ALLOWED_CLIENTS=web-app */
    static Set<String> allowedClients() {
        return csv("MFA_ALLOWED_CLIENTS", "web-app");
    }

    /** Browser origins allowed to run the WebAuthn ceremony. MFA_PLATFORM_ORIGINS=http://localhost:5173 */
    static Set<String> platformOrigins() {
        return csv("MFA_PLATFORM_ORIGINS", "http://localhost:5173");
    }

    /**
     * Origins allowed to use passkey LOGIN: the MFA Platform plus any client app that signs users in
     * (for example EduTecJob). MFA_LOGIN_ORIGINS=http://localhost:3000
     * Enrollment stays limited to platformOrigins(), so client apps can sign in but never register factors.
     */
    static Set<String> loginOrigins() {
        Set<String> origins = new HashSet<>(platformOrigins());
        origins.addAll(csv("MFA_LOGIN_ORIGINS", ""));
        return origins;
    }

    /** How recent the user's password login must be, in seconds. 0 disables the check. */
    static int reauthMaxAgeSeconds() {
        return 0;
    }
    /** Test mode: validate the passkey but do NOT store it. MFA_PASSKEY_DRY_RUN=true */
    static boolean passkeyDryRun() {
        return "true".equalsIgnoreCase(System.getenv("MFA_PASSKEY_DRY_RUN"));
    }

    private static Set<String> csv(String name, String fallback) {
        String v = System.getenv(name);
        String raw = v == null || v.isBlank() ? fallback : v;
        return Arrays.stream(raw.split(",")).map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toSet());
    }
}
