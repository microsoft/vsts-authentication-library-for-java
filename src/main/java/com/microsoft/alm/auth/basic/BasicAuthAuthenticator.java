// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth.basic;

import com.microsoft.alm.auth.BaseAuthenticator;
import com.microsoft.alm.auth.PromptBehavior;
import com.microsoft.alm.auth.secret.Credential;
import com.microsoft.alm.storage.InsecureInMemoryStore;
import com.microsoft.alm.storage.SecretStore;

import java.net.URI;

public class BasicAuthAuthenticator extends BaseAuthenticator {

    private final static String TYPE = "BasicAuth";

    private SecretStore<Credential> store;
    private CredentialPrompt prompter;

    public BasicAuthAuthenticator() {
        this(new InsecureInMemoryStore<Credential>(), new DefaultCredentialPrompt());
    }

    public BasicAuthAuthenticator(final SecretStore<Credential> store, final CredentialPrompt prompter) {
        assert store != null;
        assert prompter != null;

        this.store = store;
        this.prompter = prompter;
    }

    public String getAuthType() {
        return TYPE;
    }

    @Override
    public boolean isCredentialSupported() {
        return true;
    }

    public Credential getCredential(final URI uri) {
        return getCredential(uri, PromptBehavior.AUTO);
    }

    public Credential getCredential(final URI uri,  final PromptBehavior promptBehavior) {
        final String key = getKey(uri);

        SecretRetriever secretRetriever = new SecretRetriever() {
            @Override
            protected Credential doRetrieve() {
                return prompter.prompt(uri);
            }
        };

        return secretRetriever.retrieve(key, getStore(), promptBehavior);
    }

    @Override
    protected SecretStore<Credential> getStore() {
        return this.store;
    }
}
