// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth.oauth;

import com.microsoft.alm.auth.BaseAuthenticator;
import com.microsoft.alm.auth.PromptBehavior;
import com.microsoft.alm.auth.secret.TokenPair;
import com.microsoft.alm.storage.InsecureInMemoryStore;
import com.microsoft.alm.storage.SecretStore;

import java.net.URI;
import java.util.UUID;

public class OAuth2Authenticator extends BaseAuthenticator {

    public final static String POPUP_QUERY_PARAM = "display=popup";

    public final static URI APP_VSSPS_VISUALSTUDIO = URI.create("https://app.vssps.visualstudio.com");
    public final static String MANAGEMENT_CORE_RESOURCE = "https://management.core.windows.net/";

    private final static String TYPE = "OAuth2";

    private final String resource;
    private final String clientId;
    private final URI redirectUri;

    private final SecretStore<TokenPair> store;

    private AzureAuthority azureAuthority;

    private OAuth2Authenticator(final String resource, final String clientId, final URI redirectUri,
                               final SecretStore<TokenPair> store) {
        this.resource = resource;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.store = store == null ? new InsecureInMemoryStore<TokenPair>() : store;

        this.azureAuthority = new AzureAuthority();
    }

    /**
     * Get an OAuth2 authenticator
     *
     * @param clientId
     *      Registered OAuth2 client id
     * @param redirectUrl
     *      Callback url for the registered client
     * @param store
     *      SecretStore to read and save access token to
     *
     * @return an OAuth2Authenticator
     */
    public static OAuth2Authenticator getAuthenticator(final String clientId, final String redirectUrl,
                                                       final SecretStore<TokenPair> store) {
        return new OAuth2AuthenticatorBuilder()
                .manage(MANAGEMENT_CORE_RESOURCE)
                .withClientId(clientId)
                .redirectTo(redirectUrl)
                .backedBy(store)
                .build();
    }

    private AzureAuthority getAzureAuthority() {
        return azureAuthority;
    }

    public void setAzureAuthority(final AzureAuthority azureAuthority) {
        this.azureAuthority = azureAuthority;
    }

    public String getAuthType() {
        return this.TYPE;
    }

    @Override
    public boolean isOAuth2TokenSupported() {
        return true;
    }

    @Override
    public TokenPair getOAuth2TokenPair() {
        return getOAuth2TokenPair(PromptBehavior.AUTO);
    }

    public boolean signOut() {
        return super.signOut(APP_VSSPS_VISUALSTUDIO);
    }

    @Override
    public TokenPair getOAuth2TokenPair(final PromptBehavior promptBehavior) {
        final String key = getKey(APP_VSSPS_VISUALSTUDIO);

        SecretRetriever secretRetriever = new SecretRetriever() {
            @Override
            protected TokenPair doRetrieve() {
                final AzureAuthority authority = getAzureAuthority();
                return authority.acquireToken(clientId, resource, redirectUri, POPUP_QUERY_PARAM);
            }
        };

        return secretRetriever.retrieve(key, getStore(), promptBehavior);
    }

    @Override
    protected SecretStore<TokenPair> getStore() {
        return this.store;
    }

    public static class OAuth2AuthenticatorBuilder {
        private String resource;
        private String clientId;
        private URI redirectUri;
        private SecretStore store;

        public OAuth2AuthenticatorBuilder manage(final String resource) {
            this.resource = resource;
            return this;
        }

        public OAuth2AuthenticatorBuilder withClientId(final UUID clientId) {
            return this.withClientId(clientId.toString());
        }

        public OAuth2AuthenticatorBuilder withClientId(final String clientId) {
            this.clientId = clientId;
            return this;
        }

        public OAuth2AuthenticatorBuilder redirectTo(final URI redirectUri) {
            this.redirectUri = redirectUri;
            return this;
        }

        public OAuth2AuthenticatorBuilder redirectTo(final String redirectUri) {
            return this.redirectTo(URI.create(redirectUri));
        }

        public OAuth2AuthenticatorBuilder backedBy(final SecretStore store) {
            this.store = store;
            return this;
        }

        public OAuth2Authenticator build() {
            if (this.clientId == null) {
                throw new IllegalStateException("ClientId not set");
            }

            if (this.resource == null) {
                throw new IllegalStateException("resource not set");
            }

            if (this.redirectUri == null) {
                throw new IllegalStateException("redirectUri not set");
            }

            return new OAuth2Authenticator(this.resource, this.clientId, this.redirectUri, this.store);
        }
    }
}
