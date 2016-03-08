// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth;

import com.microsoft.alm.auth.secret.Credential;
import com.microsoft.alm.auth.secret.Token;
import com.microsoft.alm.auth.secret.TokenPair;
import com.microsoft.alm.auth.secret.VsoTokenScope;

import java.net.URI;

/**
 * Marker interface for authenticator
 */
public interface Authenticator {

    /**
     * Get the type of the authentication
     *
     * @return String representation
     */
    String getAuthType();

    /**
     * This authenticator supports returning the authorization data in the form of
     * username / password credential object
     *
     * @return true if authorization data can be represented as credential object
     */
    boolean isCredentialSupported();
    Credential getCredential(final URI key);
    Credential getCredential(final URI key, final PromptBehavior promptBehavior);

    boolean isOAuth2TokenSupported();

    TokenPair getOAuth2TokenPair();
    TokenPair getOAuth2TokenPair(final PromptBehavior promptBehavior);

    boolean isPatSupported();
    Token getPersonalAccessToken(final VsoTokenScope vsoTokenScope, final String patDisplayName,
                                 final PromptBehavior promptBehavior);

    Token getPersonalAccessToken(final URI key, final VsoTokenScope tokenScope,
                                 final String patDisplayName, final PromptBehavior promptBehavior);

    boolean signOut();
    boolean signOut(final URI key);
}
