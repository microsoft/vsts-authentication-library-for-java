// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.storage.macosx;

import com.microsoft.alm.secret.TokenPair;
import com.microsoft.alm.storage.SecretStore;

public class KeychainSecurityBackedTokenPairStore extends KeychainSecurityCliStore implements SecretStore<TokenPair> {

    @Override
    public TokenPair get(final String key) {
        return readTokenPair(key);
    }

    @Override
    public boolean add(final String key, final TokenPair secret) {
        writeTokenPair(key, secret);
        return true;
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
