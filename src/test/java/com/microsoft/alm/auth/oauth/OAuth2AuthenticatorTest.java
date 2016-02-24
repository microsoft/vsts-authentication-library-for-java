// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth.oauth;

import com.microsoft.alm.auth.secret.TokenPair;
import com.microsoft.alm.helpers.Guid;
import com.microsoft.alm.storage.SecretStore;
import org.junit.Before;
import org.junit.Test;

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

        underTest = new OAuth2Authenticator.OAuth2AuthenticatorBuilder()
                .manage("test_resource")
                .redirectTo("https://testredirect.com")
                .withClientId(clientId)
                .backedBy(mockStore)
                .build();

        underTest.setAzureAuthority(mockAzureAuthority);
    }

    @Test
    public void retrieveToken() throws URISyntaxException {
        URI uri = URI.create("http://test.com");

        when(mockAzureAuthority.getTenantId(uri)).thenReturn(Guid.Empty);
        when(mockAzureAuthority.acquireToken(uri, clientId.toString(), "test_resource",
                        new URI("https://testredirect.com"), underTest.POPUP_QUERY_PARAM + "&" + underTest
                        .MSA_QUERY_PARAMS))
                .thenReturn(new TokenPair("access", "refresh"));

        TokenPair token = underTest.getOAuth2TokenPair(uri);

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
        assertFalse(underTest.isPatSupported());
    }

}