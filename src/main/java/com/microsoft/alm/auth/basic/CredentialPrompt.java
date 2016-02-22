// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth.basic;

import com.microsoft.alm.auth.secret.Credential;

import java.net.URI;

public interface CredentialPrompt {

    /**
     * Retrieve a credential object
     *
     * @return credential
     * @param target
     */
    Credential prompt(final URI target);
}
