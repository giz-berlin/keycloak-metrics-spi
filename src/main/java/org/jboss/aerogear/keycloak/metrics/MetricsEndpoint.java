package org.jboss.aerogear.keycloak.metrics;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.StreamingOutput;

import org.jboss.logging.Logger;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.managers.AppAuthManager.BearerTokenAuthenticator;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;

public class MetricsEndpoint implements RealmResourceProvider {

    // The ID of the provider is also used as the name of the endpoint
    public final static String ID = "metrics";

    private static final boolean DISABLE_EXTERNAL_ACCESS = Boolean
            .parseBoolean(System.getenv("DISABLE_EXTERNAL_ACCESS"));

    private final static Logger logger = Logger.getLogger(MetricsEndpoint.class);

    private final Boolean bearerEnabled;
    private String bearerRole;
    private AuthResult bearerTokenAuth;

    public MetricsEndpoint(KeycloakSession session, Boolean bearerEnabled, String bearerRealm, String bearerRole) {
        super();

        this.bearerEnabled = bearerEnabled;
        if (this.bearerEnabled) {
            RealmModel realmModel = session.realms().getRealmByName(bearerRealm);
            if (realmModel == null) {
                logger.errorf("Could not find realm with name %s", bearerRealm);
                return;
            }
            session.getContext().setRealm(realmModel);
            this.bearerTokenAuth = new BearerTokenAuthenticator(session).authenticate();
            this.bearerRole = bearerRole;
        }
    }

    @Override
    public Object getResource() {
        return this;
    }

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public Response get(@Context HttpHeaders headers) {
        checkAuthentication(headers);

        final StreamingOutput stream = output -> PrometheusExporter.instance().export(output);
        return Response.ok(stream).build();
    }

    private void checkAuthentication(HttpHeaders headers) {
        if (DISABLE_EXTERNAL_ACCESS) {
            if (!headers.getRequestHeader("x-forwarded-host").isEmpty()) {
                // Request is being forwarded by HA Proxy on Openshift
                throw new ForbiddenException("X-Forwarded-Host header is present");
            }
        }

        if (this.bearerEnabled) {
            if (this.bearerTokenAuth == null) {
                throw new NotAuthorizedException("Invalid bearer token");
            } else if (this.bearerTokenAuth.getToken().getRealmAccess() == null
                    || !this.bearerTokenAuth.getToken().getRealmAccess().isUserInRole(this.bearerRole)) {
                throw new ForbiddenException("Missing required realm role");
            }
        }
    }

    @Override
    public void close() {
        // Nothing to do, no resources to close
    }
}
