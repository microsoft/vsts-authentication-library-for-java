// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.storage.macosx;

import com.microsoft.alm.secret.Credential;
import com.microsoft.alm.storage.SecretStore;

public class KeychainSecurityBackedCredentialStore extends KeychainSecurityCliStore
        implements SecretStore<Credential> {

    @Override
    public Credential get(String key) {
        return readCredentials(key);
    }

    @Override
    public boolean add(String key, Credential secret) {
        writeCredential(key, secret);
        return true;
    }

}
