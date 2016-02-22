// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.storage.windows;

import com.microsoft.alm.auth.secret.Credential;
import com.microsoft.alm.storage.windows.internal.CredManagerBackedSecureStore;

public class CredManagerBackedCredentialStore extends CredManagerBackedSecureStore<Credential> {

    @Override
    protected Credential create(final String username, final String secret) {
        return new Credential(username, secret) ;
    }

    @Override
    protected String getUsername(final Credential cred) {
        return cred.Username;
    }

    @Override
    protected String getCredentialBlob(final Credential cred) {
        return cred.Password;
    }
}
