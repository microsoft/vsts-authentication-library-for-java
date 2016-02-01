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

    public Credential getSpecificCredentialFor(final URI uri) {
        return getSpecificCredentialFor(uri, PromptBehavior.AUTO, Options.getDefaultOptions());
    }

    public Credential getSpecificCredentialFor(final URI uri, final PromptBehavior promptBehavior,
                                               final Options options) {
        if (authenticator.isCredentialSupported()) {
            final Credential credential = authenticator.getCredential(uri, promptBehavior);
            if (credential != null) {
                // defensive copy, so we never return the reference out
                return new Credential(credential.Username, credential.Password);
            }

        } else if (authenticator.isOAuth2TokenSupported()) {
            final TokenPair tokenPair = authenticator.getOAuth2TokenPair(uri, promptBehavior);

            if (tokenPair != null && tokenPair.AccessToken != null) {
                return new Credential("oauth2", tokenPair.AccessToken.Value);
            }

        } else if (authenticator.isPatSupported()) {
            final Token token = authenticator.getPersonalAccessToken(uri,
                    options.patGenerationOptions.tokenScope,
                    options.patGenerationOptions.displayName,
                    promptBehavior);

            if (token != null) {
                return new Credential("pat", token.Value);
            }
        }

        return null;
    }

    public Credential getVstsGlobalCredentials() {
        return getVstsGlobalCredentials(PromptBehavior.AUTO, Options.getDefaultOptions());
    }

    public Credential getVstsGlobalCredentials(final PromptBehavior promptBehavior, final Options options) {
        if (authenticator.isOAuth2TokenSupported()) {
            final TokenPair tokenPair = authenticator.getVstsGlobalOAuth2TokenPair(promptBehavior);

            if (tokenPair != null && tokenPair.AccessToken != null) {
                return new Credential("oauth2", tokenPair.AccessToken.Value);
            }

        } else if (authenticator.isPatSupported()) {
            final Token token = authenticator.getVstsGlobalPat(
                    options.patGenerationOptions.tokenScope,
                    options.patGenerationOptions.displayName,
                    promptBehavior);

            if (token != null) {
                return new Credential("pat", token.Value);
            }
        }

        return null;
    }

}
