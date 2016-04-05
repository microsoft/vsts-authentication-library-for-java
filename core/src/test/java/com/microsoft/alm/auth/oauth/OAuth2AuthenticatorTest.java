// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth.oauth;

import com.microsoft.alm.oauth2.useragent.AuthorizationException;
import com.microsoft.alm.secret.TokenPair;
import com.microsoft.alm.storage.SecretStore;
import org.junit.Before;
import org.junit.Test;
import org.junit.Ignore;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.UUID;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class OAuth2AuthenticatorTest {

    private OAuth2Authenticator underTest;

    private SecretStore<TokenPair> mockStore;

    private AzureAuthority mockAzureAuthority;

    private UUID clientId = UUID.randomUUID();

    @Before
    public void setUp() throws Exception {
        mockStore = mock(SecretStore.class);
        mockAzureAuthority = mock(AzureAuthority.class);

        underTest = new OAuth2Authenticator("test_resource",
                clientId.toString(),
                URI.create("https://testredirect.com"),
                mockStore,
                mockAzureAuthority);
    }

    @Test
    @Ignore
    public void retrieveToken() throws URISyntaxException, AuthorizationException {
        when(mockAzureAuthority.acquireToken(clientId.toString(), "test_resource",
                        new URI("https://testredirect.com"), underTest.POPUP_QUERY_PARAM))
                .thenReturn(new TokenPair("access", "refresh"));

        TokenPair token = underTest.getOAuth2TokenPair();

        assertEquals("access", token.AccessToken.Value);
        assertEquals("refresh", token.RefreshToken.Value);

    }

    @Test
    public void typeIsOAuth2() {
        assertEquals("OAuth2", underTest.getAuthType());
    }

    @Test
    public void oauth2IsSupported() {
        assertTrue(underTest.isOAuth2TokenSupported());

        assertFalse(underTest.isCredentialSupported());
        assertFalse(underTest.isPersonalAccessTokenSupported());
    }

}
