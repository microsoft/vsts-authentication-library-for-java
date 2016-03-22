// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.storage;

import com.microsoft.alm.secret.Secret;

import java.util.HashMap;
import java.util.Map;

public class InsecureInMemoryStore<E extends Secret> implements SecretStore<E> {

    private final Map<String, E> store;

    public InsecureInMemoryStore() {
        store = new HashMap<String, E>();
    }

    @Override
    public E get(final String key) {
        return store.get(key);
    }

    @Override
    public boolean delete(final String key) {
        if (store.containsKey(key)) {
            return store.remove(key) != null;
        }

        return true;
    }

    @Override
    public boolean add(final String key, final E secret) {
        // if there is a way to workaround Java's type erasure, I am really interested to get rid of this
        return store.put(key, secret) != null;
    }
}
