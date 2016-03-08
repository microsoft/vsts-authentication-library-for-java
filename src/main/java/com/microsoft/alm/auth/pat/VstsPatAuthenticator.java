// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth.pat;

import com.microsoft.alm.auth.BaseAuthenticator;
import com.microsoft.alm.auth.PromptBehavior;
import com.microsoft.alm.auth.oauth.OAuth2Authenticator;
import com.microsoft.alm.auth.secret.Token;
import com.microsoft.alm.auth.secret.TokenPair;
import com.microsoft.alm.auth.secret.VsoTokenScope;
import com.microsoft.alm.helpers.StringHelper;
import com.microsoft.alm.storage.SecretStore;

import java.net.URI;

public class VstsPatAuthenticator extends BaseAuthenticator {

    private final static String TYPE = "PersonalAccessToken";

    private VsoAzureAuthority vsoAzureAuthority;

    private OAuth2Authenticator vstsOauthAuthenticator;

    private SecretStore<Token> store;

    public VstsPatAuthenticator(final String oauthClientId, final String oauthClientRedirectUrl,
                                final SecretStore<TokenPair> oauthTokenStore,
                                final SecretStore<Token> store) {
        this.store = store;
        this.vstsOauthAuthenticator = OAuth2Authenticator.getAuthenticator(oauthClientId,
                oauthClientRedirectUrl, oauthTokenStore);
        this.vsoAzureAuthority = new VsoAzureAuthority();
    }

    public void setVstsOauthAuthenticator(final OAuth2Authenticator vstsOauthAuthenticator) {
        this.vstsOauthAuthenticator = vstsOauthAuthenticator;
    }

    public void setVsoAzureAuthority(final VsoAzureAuthority vsoAzureAuthority) {
        this.vsoAzureAuthority = vsoAzureAuthority;
    }

    @Override
    public boolean isPatSupported() {
        return true;
    }

    @Override
    public Token getPersonalAccessToken(final VsoTokenScope tokenScope, final String patDisplayName,
                                        final PromptBehavior promptBehavior) {

        return getToken(vstsOauthAuthenticator.APP_VSSPS_VISUALSTUDIO, true, tokenScope, patDisplayName, promptBehavior);
    }

    @Override
    public Token getPersonalAccessToken(final URI uri, final VsoTokenScope tokenScope, final String patDisplayName,
                                        final PromptBehavior promptBehavior) {
        return getToken(uri, false, tokenScope, patDisplayName, promptBehavior);
    }

    private Token getToken(final URI uri, final boolean isCreatingGlobalPat,
                           final VsoTokenScope tokenScope, final String patDisplayName,
                           final PromptBehavior promptBehavior) {
        if (!isHosted(uri)) {
            throw new RuntimeException("Only works against VisualStudio Team Services");
        }

        final String key = getKey(uri);

        SecretRetriever secretRetriever = new SecretRetriever() {
            @Override
            protected Token doRetrieve() {
                TokenPair oauthToken = vstsOauthAuthenticator.getOAuth2TokenPair(promptBehavior.AUTO);

                if (oauthToken == null) {
                    // authentication failed, return null
                    return null;
                }

                if (oauthToken != null) {
                    final Token token = vsoAzureAuthority.generatePersonalAccessToken(uri, oauthToken.AccessToken,
                            tokenScope, true, isCreatingGlobalPat, patDisplayName);

                    return token;
                }

                return null;
            }
        };

        return secretRetriever.retrieve(key, getStore(), promptBehavior);
    }

    /**
     * "Forget" the global PAT, also remove the oauth token to force sign in again
     *
     * @return {@code true} if global PAT and the OAuth2 token used to generate this PAT are both forgotten
     */
    @Override
    public boolean signOut() {
        return this.signOut(vstsOauthAuthenticator.APP_VSSPS_VISUALSTUDIO);
    }

    @Override
    public boolean signOut(final URI uri) {
        return super.signOut(uri)
                && vstsOauthAuthenticator.signOut();
    }

    public boolean assignGlobalPatTo(final URI uri) {
        final String globalKey = getKey(vstsOauthAuthenticator.APP_VSSPS_VISUALSTUDIO);
        final Token token = getStore().get(globalKey);
        if (token != null) {
            assign(uri, token);
            return true;
        }

        return false;
    }

    public void assign(final URI uri, final Token token) {
        final String key = getKey(uri);
        getStore().add(key, token);
    }

    @Override
    protected SecretStore<Token> getStore() {
        return this.store;
    }

    @Override
    public String getAuthType() {
        return TYPE;
    }

    private boolean isHosted(final URI targetUri) {
        final String VsoBaseUrlHost = "visualstudio.com";
        return StringHelper.endsWithIgnoreCase(targetUri.getHost(), VsoBaseUrlHost);
    }

}
