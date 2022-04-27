package org.jboss.aerogear.keycloak.metrics;

import org.jboss.logging.Logger;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.managers.AppAuthManager.BearerTokenAuthenticator;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;
import org.keycloak.services.resource.RealmResourceProvider;

import javax.ws.rs.GET;
import javax.ws.rs.Produces;
import javax.ws.rs.ForbiddenException;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.StreamingOutput;
import javax.ws.rs.core.Response.Status;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;

public class MetricsEndpoint implements RealmResourceProvider {

    // The ID of the provider is also used as the name of the endpoint
    public final static String ID = "metrics";

    private static final boolean DISABLE_EXTERNAL_ACCESS = Boolean.parseBoolean(System.getenv("DISABLE_EXTERNAL_ACCESS"));

    private final static Logger logger = Logger.getLogger(MetricsEndpoint.class);

    private Boolean bearerEnabled;
    private String role;
    private AuthResult auth;

    public MetricsEndpoint(KeycloakSession session, Boolean bearerEnabled, String realm, String role) {
        super();

        this.bearerEnabled = bearerEnabled;
        if (this.bearerEnabled) {
            RealmModel realmModel = session.realms().getRealmByName(realm);
            if (realmModel == null) {
                logger.errorf("Could not find realm with name %s", realm);
                return;
            }
            session.getContext().setRealm(realmModel);
            this.auth = new BearerTokenAuthenticator(session).authenticate();
            this.role = role;
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
                throw new NotAuthorizedException("X-Forwarded-Host header is present");
            }
        }

        if (this.bearerEnabled) {
            if (this.auth == null) {
                throw new NotAuthorizedException("Invalid bearer token");
            } else if (this.auth.getToken().getRealmAccess() == null || !this.auth.getToken().getRealmAccess().isUserInRole(this.role)) {
                throw new ForbiddenException("Missing required realm role");
            }
        }
    }

    @Override
    public void close() {
        // Nothing to do, no resources to close
    }
}
