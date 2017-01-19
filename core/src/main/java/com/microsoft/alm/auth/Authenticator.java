// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth;

import com.microsoft.alm.secret.Credential;
import com.microsoft.alm.secret.Secret;
import com.microsoft.alm.secret.Token;
import com.microsoft.alm.secret.TokenPair;
import com.microsoft.alm.secret.VsoTokenScope;

import java.net.URI;

/**
 * Authenticator that retrieves credentials against Visual Studio Team Services instances or
 * Team Foundation Servers.
 */
public interface Authenticator {

    /**
     * Get the type of the authentication provided by this authenticator
     *
     * Possible types are:
     *   BasicAuth:
     *          Username and Password combo
     *   OAuth2:
     *          OAuth2 token to access Azure protected resource
     *   PersonalAccessToken:
     *          Personal Access Token generated against Visual Studio Team Services
     *
     * @return String representation of the type
     */
    String getAuthType();

    /**
     * Get the converter that maps URIs to secret key names
     *
     * @return an implementation of {@link com.microsoft.alm.secret.Secret.IUriNameConversion}
     */
    Secret.IUriNameConversion getUriToKeyConversion();

    /**
     * Set the converter that maps URIs to secret key names
     *
     * @param conversion an implementation of {@link com.microsoft.alm.secret.Secret.IUriNameConversion}
     */
    void setUriToKeyConversion(final Secret.IUriNameConversion conversion);

    /**
     * Checks to see if this authenticator supports returning the authorization data in the form of
     * username / password {@link Credential} object
     *
     * @return {@code true} if this authenticator can retrieve a credential object
     *         {@code false} otherwise
     */
    boolean isCredentialSupported();

    /**
     * Retrieve credential for the specified URI with {@link PromptBehavior} AUTO
     *
     * @param key
     *      URI identifies the resource been requested
     *
     * @return
     *      Credential that can be used to access the resource
     */
    Credential getCredential(final URI key);

    /**
     * Retrieve credential for the specified URI with specified {@link PromptBehavior}
     *
     * @param key
     *      URI identifies the resource been requested
     * @param promptBehavior
     *      dictates whether we should prompt the user for input or not
     *
     * @return
     *      Credential that can be used to access the resource
     */
    Credential getCredential(final URI key, final PromptBehavior promptBehavior);

    /**
     * Checks to see if this authenticator supports returning the authorization data in the form of
     * an OAuth2 token pair, which has one access token and a refresh token
     *
     * @return {@code true} if this authenticator can retrieve {@link TokenPair}
     *         {@code false} otherwise
     */
    boolean isOAuth2TokenSupported();

    /**
     * Retrieve an OAuth2 {@link TokenPair} token pair (access token / refresh token) from Azure AD
     * with {@link PromptBehavior} AUTO
     *
     * https://msdn.microsoft.com/en-us/library/azure/dn645545.aspx
     *
     * @return an OAuth2 TokenPair from Azure AD
     */
    TokenPair getOAuth2TokenPair();

    /**
     * Retrieve an OAuth2 {@link TokenPair} token pair (access token / refresh token) from Azure AD
     * with specified {@link PromptBehavior}
     *
     * https://msdn.microsoft.com/en-us/library/azure/dn645545.aspx
     *
     * @param promptBehavior
     *      dictates whether we should prompt the user for input or not
     *
     * @return an OAuth2 TokenPair from Azure AD
     */
    TokenPair getOAuth2TokenPair(final PromptBehavior promptBehavior);

    /**
     * Retrieve an OAuth2 {@link TokenPair} token pair (access token / refresh token) from the tenant that backs
     * the target URI from Azure AD with specified {@link PromptBehavior}
     *
     * https://msdn.microsoft.com/en-us/library/azure/dn645545.aspx
     *
     * @param uri
     *      a vsts account url, the retrieved OAuth2 token will be from the same tenant
     * @param promptBehavior
     *      dictates whether we should prompt the user for input or not
     *
     * @return an OAuth2 TokenPair from Azure AD
     */
    TokenPair getOAuth2TokenPair(final URI uri, final PromptBehavior promptBehavior);

    /**
     * Checks to see if this authenticator supports get a Personal Access {@link Token} object from
     * Visual Studio Team Services
     *
     * @return {@code true} if this authenticator supports retrieving PAT
     *         {@code false} otherwise
     */
    boolean isPersonalAccessTokenSupported();

    /**
     * @deprecated Global Personal Access Token is going away soon, no replacement as of yet.  Please generate
     * PAT specific to accounts with {@link #getPersonalAccessToken(URI, VsoTokenScope, String, PromptBehavior)}
     *
     * Retrieve a global Personal Access {@link Token} that works across all accounts the user owns.
     * <p>
     * Favor existing global PAT available from the store unless override from the {@link PromptBehavior}.
     * <p>
     * If there are no existing Global PAT, and prompting is allowed, we will generate a PAT with the given
     * {@link VsoTokenScope} and display name.
     *
     *
     * @param vsoTokenScope
     *      If we are generating token, the scope of the newly generated token
     * @param patDisplayName
     *      If we are generating token, the display name of the token
     * @param promptBehavior
     *      dictates whether we should prompt the user for input or not
     *
     * @return global Personal Access Token
     */
    @Deprecated
    Token getPersonalAccessToken(final VsoTokenScope vsoTokenScope, final String patDisplayName,
                                 final PromptBehavior promptBehavior);
    /**
     * Retrieve a Personal Access {@link Token} that works for the specified account URI.
     * <p>
     * Favor existing token available from the store unless override from the {@link PromptBehavior}.
     * <p>
     * If there are no existing PAT, and prompting is allowed, we will generate a PAT with the given
     * {@link VsoTokenScope} and display name.
     *
     * @param key
     *      The account URI we will be retrieve PAT for
     * @param tokenScope
     *      If we are generating token, the scope of the newly generated token
     * @param patDisplayName
     *      If we are generating token, the display name of the token
     * @param promptBehavior
     *      dictates whether we should prompt the user for input or not
     *
     * @return a Personal Access Token scoped to the specified account URI
     */
    Token getPersonalAccessToken(final URI key, final VsoTokenScope tokenScope,
                                 final String patDisplayName, final PromptBehavior promptBehavior);

    /**
     * Retrieve a Personal Access {@link Token} that works for the specified account URI.
     * <p>
     * Favor existing token available from the store unless override from the {@link PromptBehavior}.
     * <p>
     * If there are no existing PAT, and prompting is allowed, we will generate a PAT with the given
     * {@link VsoTokenScope} and display name.
     *
     * @param key
     *      The account URI we will be retrieve PAT for
     * @param tokenScope
     *      If we are generating token, the scope of the newly generated token
     * @param patDisplayName
     *      If we are generating token, the display name of the token
     * @param promptBehavior
     *      dictates whether we should prompt the user for input or not
     * @param oauth2Token
     *      if oauth2Token is not null, use it and do not prompt to login via browser
     *
     * @return a Personal Access Token scoped to the specified account URI
     */
    Token getPersonalAccessToken(final URI key, final VsoTokenScope tokenScope,
                                 final String patDisplayName, final PromptBehavior promptBehavior,
                                 final TokenPair oauth2Token);

    /**
     * Sign out globally from this library only.  This function does not perform any server calls to sign the
     * user out.
     *
     * @return {@code true} if the global secret is removed from this library
     *         {@code false} otherwise
     */
    boolean signOut();

    /**
     * Sign out from this particular URI from this library only.  This function does not perform any server calls to
     * sign the user out on the server.
     *
     * @param key
     *      Forget the secret stored for the account identified by this URI key
     *
     * @return {@code true} if the global secret is removed from this library
     *         {@code false} otherwise
     */
    boolean signOut(final URI key);
}
