// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth.basic;

import com.microsoft.alm.secret.Credential;

import java.net.URI;

public interface CredentialPrompt {

    /**
     * Retrieve a credential object
     *
     * @param target
     *      the resource we are trying to manage
     *
     * @return user entered credential
     */
    Credential prompt(final URI target);
}
