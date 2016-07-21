// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.storage.macosx;

import com.microsoft.alm.secret.Token;
import com.microsoft.alm.storage.SecretStore;

public class KeychainSecurityBackedTokenStore extends KeychainSecurityCliStore implements SecretStore<Token> {

    @Override
    public Token get(String key) {
        return readToken(key);
    }

    @Override
    public boolean add(String key, Token secret) {
        writeToken(key, secret);
        return true;
    }

    @Override
    public boolean delete(final String targetName) {
        return deleteByKind(targetName, SecretKind.Token);
    }

    /**
     * Keychain Access is secure
     *
     * @return {@code true} for Keychain Access
     */
    @Override
    public boolean isSecure() {
        return true;
    }
}
