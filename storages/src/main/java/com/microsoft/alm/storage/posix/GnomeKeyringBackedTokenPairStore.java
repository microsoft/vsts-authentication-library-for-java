// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.storage.posix;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.microsoft.alm.helpers.Debug;
import com.microsoft.alm.secret.Credential;
import com.microsoft.alm.secret.TokenPair;
import com.microsoft.alm.storage.posix.internal.GnomeKeyringBackedSecureStore;

import java.io.IOException;

public class GnomeKeyringBackedTokenPairStore extends GnomeKeyringBackedSecureStore<TokenPair> {

    private static final ObjectMapper mapper = new ObjectMapper();

    static {
        mapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);
    }

    @Override
    protected String serialize(TokenPair tokenPair) {
        Debug.Assert(tokenPair != null, "TokenPair cannot be null");

        final TokenPairWrapper wrapper = new TokenPairWrapper();
        wrapper.setAccessToken(tokenPair.AccessToken.Value);
        wrapper.setRefreshToken(tokenPair.RefreshToken.Value);

        try {
            return mapper.writeValueAsString(wrapper);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected TokenPair deserialize(String secret) {
        Debug.Assert(secret != null, "secret cannot be null");

        try {
            final TokenPairWrapper tokenPairWrapper = mapper.readValue(secret, TokenPairWrapper.class);

            return new TokenPair(tokenPairWrapper.accessToken, tokenPairWrapper.refreshToken);
        } catch (IOException e) {
            return null;
        }
    }

    @Override
    protected String getType() {
        return "OAuth2Token";
    }

    public static class TokenPairWrapper {
        private String accessToken;
        private String refreshToken;

        public void setAccessToken(final String accessToken) {
            this.accessToken = accessToken;
        }

        public void setRefreshToken(final String refreshToken) {
            this.refreshToken = refreshToken;
        }
    }
}
