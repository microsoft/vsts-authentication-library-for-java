// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.storage.windows;

import com.microsoft.alm.common.secret.Token;
import com.microsoft.alm.common.secret.TokenType;
import com.microsoft.alm.storage.windows.internal.CredManagerBackedSecureStore;

public class CredManagerBackedTokenStore extends CredManagerBackedSecureStore<Token> {

    public static final String TOKEN_USERNAME = "PersonalAccessToken";

    @Override
    protected Token create(final String username, final String secret) {
        return new Token(secret, TokenType.Personal);
    }

    @Override
    protected String getUsername(final Token token) {
        return TOKEN_USERNAME;
    }

    @Override
    protected String getCredentialBlob(final Token token) {
        return token.Value;
    }
}
