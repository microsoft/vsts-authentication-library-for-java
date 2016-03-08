// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.provider;

import com.microsoft.alm.auth.Authenticator;
import com.microsoft.alm.auth.PromptBehavior;
import com.microsoft.alm.auth.secret.Credential;
import com.microsoft.alm.auth.secret.Token;
import com.microsoft.alm.auth.secret.TokenPair;

import java.net.URI;

public class UserPasswordCredentialProvider {

    private Authenticator authenticator;

    public UserPasswordCredentialProvider(final Authenticator authenticator) {
        this.authenticator = authenticator;
    }

    public Credential getCredential() {
        return getCredentials(PromptBehavior.AUTO, Options.getDefaultOptions());
    }

    public Credential getCredentials(final PromptBehavior promptBehavior, final Options options) {

        final String username = authenticator.getAuthType();

        String password = null;
        if (authenticator.isOAuth2TokenSupported()) {
            final TokenPair tokenPair = authenticator.getOAuth2TokenPair(promptBehavior);

            if (tokenPair != null && tokenPair.AccessToken != null) {
                password = tokenPair.AccessToken.Value;
            }

        } else if (authenticator.isPersonalAccessTokenSupported()) {
            final Token token = authenticator.getPersonalAccessToken(
                    options.patGenerationOptions.tokenScope,
                    options.patGenerationOptions.displayName,
                    promptBehavior);

            if (token != null) {
                password = token.Value;
            }
        }

        return createCreds(username, password);
    }

    public Credential getCredentialFor(final URI uri) {
        return getCredentialFor(uri, PromptBehavior.AUTO, Options.getDefaultOptions());
    }

    public Credential getCredentialFor(final URI uri, final PromptBehavior promptBehavior,
                                       final Options options) {
        String username = null;
        String password = null;

        if (authenticator.isCredentialSupported()) {
            final Credential credential = authenticator.getCredential(uri, promptBehavior);
            if (credential != null) {
                username = credential.Username;
                password = credential.Password;
            }

        } else if (authenticator.isOAuth2TokenSupported()) {
            final TokenPair tokenPair = authenticator.getOAuth2TokenPair(promptBehavior);

            if (tokenPair != null && tokenPair.AccessToken != null) {
                username = authenticator.getAuthType();
                password = tokenPair.AccessToken.Value;
            }

        } else if (authenticator.isPersonalAccessTokenSupported()) {
            final Token token = authenticator.getPersonalAccessToken(uri,
                    options.patGenerationOptions.tokenScope,
                    options.patGenerationOptions.displayName,
                    promptBehavior);

            if (token != null) {
                username = authenticator.getAuthType();
                password = token.Value;
            }
        }

        return createCreds(username, password);
    }

    private Credential createCreds(final String username, final String password) {
        return (username != null && password != null) ? new Credential(username, password) : null;
    }
}
