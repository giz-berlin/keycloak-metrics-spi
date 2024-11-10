package org.jboss.aerogear.keycloak.metrics;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class MetricsEndpointFactory implements RealmResourceProviderFactory {

    private static final String BEARER_ENABLED_CONFIGURATION = "bearerEnabled";
    private static final String BEARER_REALM_CONFIGURATION = "realm";
    private static final String DEFAULT_BEARER_REALM = "master";
    private static final String BEARER_ROLE_CONFIGURATION = "role";
    private static final String DEFAULT_BEARER_ROLE = "prometheus-metrics";

    private Boolean bearerEnabled;
    private String bearerRealm;
    private String bearerRole;

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new MetricsEndpoint(session, this.bearerEnabled, this.bearerRealm, this.bearerRole);
    }

    @Override
    public void init(Config.Scope config) {
        this.bearerEnabled = config.getBoolean(BEARER_ENABLED_CONFIGURATION, false);
        this.bearerRealm = config.get(BEARER_REALM_CONFIGURATION, DEFAULT_BEARER_REALM);
        this.bearerRole = config.get(BEARER_ROLE_CONFIGURATION, DEFAULT_BEARER_ROLE);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // nothing to do
    }

    @Override
    public void close() {
        // nothing to close
    }

    @Override
    public String getId() {
        return MetricsEndpoint.ID;
    }
}
