// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.provider;

import com.microsoft.alm.auth.Authenticator;
import com.microsoft.alm.auth.PromptBehavior;
import com.microsoft.alm.auth.secret.Credential;
import com.microsoft.alm.auth.secret.Token;
import com.microsoft.alm.auth.secret.TokenPair;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.glassfish.jersey.apache.connector.ApacheClientProperties;
import org.glassfish.jersey.apache.connector.ApacheConnectorProvider;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.client.RequestEntityProcessing;
import org.glassfish.jersey.client.spi.ConnectorProvider;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.client.ClientRequestFilter;
import java.io.IOException;
import java.net.URI;

/**
 * TODO: we need to add proxy setting and such
 */
public class JaxrsClientProvider {

    private Authenticator authenticator;

    public JaxrsClientProvider(final Authenticator authenticator) {
        this.authenticator = authenticator;
    }

    public Client getSpecificClientFor(final URI uri) {
        return getSpecificClientFor(uri, PromptBehavior.AUTO, Options.getDefaultOptions());
    }

    public Client getSpecificClientFor(final URI uri, final PromptBehavior promptBehavior, final Options options) {
        // default Jersey client with HttpURLConnection as the connector

        if (authenticator.isCredentialSupported()) {
            final Credential credential = authenticator.getCredential(uri, promptBehavior);
            if (credential != null) {
                final ClientConfig clientConfig
                        = getClientConfig(new Credential(credential.Username, credential.Password));

                return ClientBuilder.newClient(clientConfig);
            }
        } else if (authenticator.isOAuth2TokenSupported()) {
            final TokenPair tokenPair = authenticator.getOAuth2TokenPair(uri, promptBehavior);
            if (tokenPair != null && tokenPair.AccessToken != null) {
                final Client client = ClientBuilder.newClient();
                client.register(new ClientRequestFilter() {
                    @Override
                    public void filter(final ClientRequestContext requestContext) throws IOException {
                        requestContext.getHeaders().putSingle("Authorization", "Bearer " + tokenPair.AccessToken.Value);
                    }
                });

                return client;
            }
        } else if (authenticator.isPatSupported()) {
            final Token token = authenticator.getPersonalAccessToken(uri,
                    options.patGenerationOptions.tokenScope,
                    options.patGenerationOptions.displayName,
                    promptBehavior);

            if (token != null) {
                final ClientConfig clientConfig = getClientConfig(new Credential("pat", token.Value));
                return ClientBuilder.newClient(clientConfig);
            }
        }

        return null;
    }

    public Client getVstsGlobalClient() {
        return getVstsGlobalClient(PromptBehavior.AUTO, Options.getDefaultOptions());
    }

    public Client getVstsGlobalClient(final PromptBehavior promptBehavior, final Options options) {
        if (authenticator.isOAuth2TokenSupported()) {
            final TokenPair tokenPair = authenticator.getVstsGlobalOAuth2TokenPair(promptBehavior);

            if (tokenPair != null && tokenPair.AccessToken != null) {
                final Client client = ClientBuilder.newClient();
                client.register(new ClientRequestFilter() {
                    @Override
                    public void filter(final ClientRequestContext requestContext) throws IOException {
                        requestContext.getHeaders().putSingle("Authorization", "Bearer " + tokenPair.AccessToken.Value);
                    }
                });

                return client;
            }

        } else if (authenticator.isPatSupported()) {
            final Token token = authenticator.getVstsGlobalPat(
                    options.patGenerationOptions.tokenScope,
                    options.patGenerationOptions.displayName,
                    promptBehavior);
            if (token != null) {
                final ClientConfig clientConfig = getClientConfig(new Credential("pat", token.Value));

                return ClientBuilder.newClient(clientConfig);
            }
        }

        return null;
    }

    private static ClientConfig getClientConfig(final Credential patCredential) {
        final Credentials credentials
                = new UsernamePasswordCredentials(patCredential.Username, patCredential .Password);

        final CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
        credentialsProvider.setCredentials(AuthScope.ANY, credentials);

        final ConnectorProvider connectorProvider = new ApacheConnectorProvider();

        final ClientConfig clientConfig = new ClientConfig().connectorProvider(connectorProvider);
        clientConfig.property(ApacheClientProperties.CREDENTIALS_PROVIDER, credentialsProvider);

        clientConfig.property(ApacheClientProperties.PREEMPTIVE_BASIC_AUTHENTICATION, true);
        clientConfig.property(ClientProperties.REQUEST_ENTITY_PROCESSING, RequestEntityProcessing.BUFFERED);

        return clientConfig;
    }

}
