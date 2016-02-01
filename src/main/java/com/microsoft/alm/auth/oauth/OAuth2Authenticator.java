// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth.oauth;

import com.microsoft.alm.auth.BaseAuthenticator;
import com.microsoft.alm.auth.PromptBehavior;
import com.microsoft.alm.auth.secret.TokenPair;
import com.microsoft.alm.helpers.Guid;
import com.microsoft.alm.storage.InsecureInMemoryStore;
import com.microsoft.alm.storage.SecretStore;

import java.net.URI;
import java.util.UUID;

public class OAuth2Authenticator extends BaseAuthenticator {

    public final static String MANAGEMENT_CORE_RESOURCE = "https://management.core.windows.net/";
    public final static String VSTS_RESOURCE = "499b84ac-1321-427f-aa17-267ca6975798";

    public final static URI APP_VSSPS_VISUALSTUDIO = URI.create("https://app.vssps.visualstudio.com");
    public final static String MSA_QUERY_PARAMS = "domain_hint=live.com&display=popup&site_id=501454&nux=1";

    private final static String TYPE = "OAuth2";

    private String resource;
    private String clientId;
    private URI redirectUri;

    private SecretStore<TokenPair> store;

    private AzureAuthority azureAuthority;

    public OAuth2Authenticator(final String resource, final String clientId, final URI redirectUri) {
        this(resource, clientId, redirectUri, new InsecureInMemoryStore<TokenPair>());
    }

    public OAuth2Authenticator(final String resource, final String clientId, final URI redirectUri,
                               final SecretStore<TokenPair> store) {
        this.resource = resource;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.store = store == null ? new InsecureInMemoryStore<TokenPair>() : store;

        this.azureAuthority = new AzureAuthority();
    }

    public static OAuth2Authenticator getGlobalAuthenticator(final String clientId, final String redirectUrl,
                                                                 final SecretStore<TokenPair> store) {
        return new OAuth2AuthenticatorBuilder()
                .manage(MANAGEMENT_CORE_RESOURCE)
                .withClientId(clientId)
                .redirectTo(redirectUrl)
                .backedBy(store)
                .build();
    }

    /**
     * WARNING: Please be careful when using this authenticator
     *
     * This may save you one redirect from the web so it takes you directly to either live login page or
     * AAD tenant login page provided you specified a specific URI so we can figure the information out.
     *
     * If you use this and target URI where we can't figure out the tenant info, the returned OAuth token won't work.
     * For example, if you use this and target "https://app.vssps.visualstudio.com", you will get a token, but that
     * token won't work for any subsequent calls.
     *
     * @param clientId
     * @param store
     * @return an OAuth2Authenticator that works only in specific situation.  Use this only when you are sure you will
     * always target a specific uri.
     */
    public static OAuth2Authenticator getAccountLevelAuthenticator(final String clientId, final String redirectUrl,
                                                                 final SecretStore<TokenPair> store) {
        return new OAuth2AuthenticatorBuilder()
                .manage(VSTS_RESOURCE)
                .withClientId(clientId)
                .redirectTo(redirectUrl)
                .backedBy(store)
                .build();
    }

    public AzureAuthority getAzureAuthority() {
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
    public TokenPair getVstsGlobalOAuth2TokenPair(final PromptBehavior promptBehavior) {
        return getOAuth2TokenPair(APP_VSSPS_VISUALSTUDIO, promptBehavior);
    }

    public boolean signOutGlobally() {
        return signOut(APP_VSSPS_VISUALSTUDIO);
    }

    @Override
    public TokenPair getOAuth2TokenPair(final URI uri) {
        return getOAuth2TokenPair(uri, PromptBehavior.AUTO);
    }

    @Override
    public TokenPair getOAuth2TokenPair(final URI uri, final PromptBehavior promptBehavior) {
        final String key = getKey(uri);

        SecretRetriever secretRetriever = new SecretRetriever() {
            @Override
            protected TokenPair doRetrieve() {
                final String queryParam;
                final AzureAuthority authority = getAzureAuthority();

                if (isManageCoreWindowsNetResource()) {
                    // skip all tenant detection, use common tenant
                    queryParam = null;
                } else {
                    final UUID tenantId = authority.getTenantId(uri);
                    if (tenantId != null && isMSA(tenantId)) {
                        queryParam = MSA_QUERY_PARAMS;
                        authority.setAuthorityHostUrl(azureAuthority.MSAAuthorityHostUrl);
                    } else {
                        queryParam = null;
                    }
                }

                return authority.acquireToken(uri, clientId, resource, redirectUri, queryParam);
            }
        };

        return secretRetriever.retrieve(key, getStore(), promptBehavior);
    }

    @Override
    protected SecretStore<TokenPair> getStore() {
        return this.store;
    }

    private boolean isManageCoreWindowsNetResource() {
        return this.resource.equals(MANAGEMENT_CORE_RESOURCE);
    }

    private boolean isMSA(final UUID tenantId) {
        return Guid.Empty.equals(tenantId);
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
