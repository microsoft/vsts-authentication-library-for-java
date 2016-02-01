// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.storage;

import com.microsoft.alm.auth.secret.Secret;

public interface SecretStore<E extends Secret> {

    E get(final String key);

    boolean delete(final String key);

    void add(final String key, final E secret);
}
