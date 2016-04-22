// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.storage.posix;

import com.microsoft.alm.secret.Token;
import com.microsoft.alm.secret.TokenType;
import com.microsoft.alm.storage.posix.internal.GnomeKeyringBackedSecureStore;

public class GnomeKeyringBackedTokenStore extends GnomeKeyringBackedSecureStore<Token> {

    @Override
    protected Token deserialize(final String secret) {
        return new Token(secret, TokenType.Personal);
    }

    @Override
    protected String serialize(final Token secret) {
        return secret.Value;
    }

    @Override
    protected String getType() {
        return "PersonalAccessToken";
    }
}
