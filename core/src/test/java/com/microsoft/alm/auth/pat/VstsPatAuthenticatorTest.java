// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth.pat;

import com.microsoft.alm.auth.PromptBehavior;
import com.microsoft.alm.auth.oauth.OAuth2Authenticator;
import com.microsoft.alm.secret.Token;
import com.microsoft.alm.secret.TokenPair;
import com.microsoft.alm.secret.TokenType;
import com.microsoft.alm.secret.VsoTokenScope;
import com.microsoft.alm.storage.SecretStore;
import org.junit.Before;
import org.junit.Test;

import java.net.URI;

import static junit.framework.Assert.assertEquals;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class VstsPatAuthenticatorTest {

    private VstsPatAuthenticator underTest;

    private VsoAzureAuthority mockVsoAzureAuthority;

    private OAuth2Authenticator mockVstsOauthAuthenticator;

    private SecretStore<Token> tokenStore;

    @Before
    public void setUp() throws Exception {
        tokenStore = mock(SecretStore.class);
        mockVsoAzureAuthority = mock(VsoAzureAuthority.class);
        mockVstsOauthAuthenticator = mock(OAuth2Authenticator.class);

        underTest = new VstsPatAuthenticator(mockVsoAzureAuthority, mockVstsOauthAuthenticator, tokenStore);
    }

    @Test
    public void testGetPersonalAccessToken() throws Exception {
        URI uri = URI.create("https://testuri.visualstudio.com");
        TokenPair tokenPair = new TokenPair("access", "refresh");
        when(mockVstsOauthAuthenticator.getOAuth2TokenPair(PromptBehavior.NEVER)).thenReturn(null);
        when(mockVstsOauthAuthenticator.getOAuth2TokenPair(PromptBehavior.AUTO)).thenReturn(tokenPair);

        when(mockVsoAzureAuthority.generatePersonalAccessToken(uri, tokenPair.AccessToken, VsoTokenScope.AllScopes, true,
                false, "PAT")).thenReturn(new Token("token", TokenType.Personal));

        Token token = underTest.getPersonalAccessToken(uri, VsoTokenScope.AllScopes, "PAT", PromptBehavior.AUTO);

        assertEquals("token", token.Value);
    }

    @Test
    public void testGetAuthType() throws Exception {
        assertEquals("PersonalAccessToken", underTest.getAuthType());
    }

    @Test
    public void patIsSupported() {
        assertTrue(underTest.isPersonalAccessTokenSupported());

        assertFalse(underTest.isOAuth2TokenSupported());
        assertFalse(underTest.isCredentialSupported());
    }
}