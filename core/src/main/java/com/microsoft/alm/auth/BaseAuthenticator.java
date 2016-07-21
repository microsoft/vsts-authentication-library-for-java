// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth;

import com.microsoft.alm.secret.Credential;
import com.microsoft.alm.secret.Secret;
import com.microsoft.alm.secret.Token;
import com.microsoft.alm.secret.TokenPair;
import com.microsoft.alm.secret.VsoTokenScope;
import com.microsoft.alm.helpers.Debug;
import com.microsoft.alm.storage.SecretStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;

/**
 * Abstract authenticator with default implementations
 *
 * Real authenticator should extend this no op authenticator, and they do not have to implement
 * methods that don't make sense to them
 */
public abstract class BaseAuthenticator implements Authenticator {

    private static final Logger logger = LoggerFactory.getLogger(BaseAuthenticator.class);

    protected Secret.IUriNameConversion uriToKeyConversion = Secret.DefaultUriNameConversion;

    @Override
    public Secret.IUriNameConversion getUriToKeyConversion() {
        return uriToKeyConversion;
    }

    @Override
    public void setUriToKeyConversion(final Secret.IUriNameConversion conversion) {
        uriToKeyConversion = conversion;
    }

    @Override
    public boolean isCredentialSupported() {
        return false;
    }

    @Override
    public Credential getCredential(final URI key) {
        return null;
    }

    @Override
    public Credential getCredential(final URI key, final PromptBehavior promptBehavior) {
        return null;
    }

    @Override
    public boolean isOAuth2TokenSupported() {
        return false;
    }

    @Override
    public TokenPair getOAuth2TokenPair() {
        return null;
    }

    @Override
    public TokenPair getOAuth2TokenPair(final PromptBehavior promptBehavior) {
        return null;
    }

    @Override
    public boolean isPersonalAccessTokenSupported() {
        return false;
    }

    @Override
    public Token getPersonalAccessToken(final VsoTokenScope tokenScope, final String patDisplayName,
                                        final PromptBehavior promptBehavior) {
        return null;
    }

    @Override
    public Token getPersonalAccessToken(final URI key, final VsoTokenScope tokenScope,
                                        final String patDisplayName, final PromptBehavior promptBehavior) {
        return null;
    }

    @Override
    public boolean signOut() {
        return false;
    }

    @Override
    public boolean signOut(final URI uri) {
        Debug.Assert(uri != null, "uri cannot be null");

        logger.debug("Signing out from uri: {}", uri);
        final String key = getKey(uri);
        Debug.Assert(key != null, "key conversion failed");

        synchronized (getStore()) {
            logger.debug("Deleting secret for {}", key);
            return getStore().delete(key);
        }
    }

    /**
     * Keys are separated by name space, which are just the authentication type of this Authentcator
     *
     * So a PAT key will be different from an OAuth2 Key even for the same URI
     *
     * @param targetUri
     *      the URL we are trying to authenticate
     *
     * @return key used to retrieve and store secrets in a secret store
     */
    public String getKey(final URI targetUri) {
        logger.debug("Getting secret for uri: {}", targetUri);
        return this.uriToKeyConversion.convert(targetUri, getAuthType());
    }

    protected abstract SecretStore getStore();

    /**
     * Common pattern to retrieve a secret from store based on supplied prompt behavior
     *
     * TODO: should we also add validation behavior extension point here?
     */
    public static abstract class SecretRetriever<E extends Secret> {
        /**
         * Standard synchronized access to store.  Extensibility point that
         * can be overridden
         *
         * @param key
         *      key for that credentials are saved under
         * @param store
         *      a secret store that holds credentials
         *
         * @return stored secret based on key, nullable
         */
        protected E readFromStore(final String key, final SecretStore<E> store) {
            synchronized (store) {
                return store.get(key);
            }
        }

        /**
         * How the secret is generated / retrieved.  This is the real work
         *
         * @return secret
         */
        protected abstract E doRetrieve();

        /**
         * Standard storing the secret based on the key
         *
         * This is an extensibility point.
         *
         * @param key
         *      key for that credentials are saved under
         * @param store
         *      a secret store that holds credentials
         *
         * @param secret
         *      secret to be saved in the store
         */
        protected void store(final String key, final SecretStore<E> store, E secret) {
            if (secret != null) {
                logger.debug("Storing secret for key: {}.", key);
                synchronized (store) {
                    store.add(key, secret);
                }
            }
        }

        /**
         * The main logic for retrieving a key.
         *
         * Depending on the {@code PromptBehavior} passed in, we should either prompt the user or
         * return null when we couldn't retrieve credential based on the key from the specified store
         *
         * @param key
         *      key for that credentials are saved under
         * @param store
         *      a secret store that holds credentials
         * @param promptBehavior
         *      determines whether we should prompt or not if we don't have a credential for the specified key
         *
         * @return secret
         *      secret to be saved in the store
         */
        public E retrieve(final String key, final SecretStore<E> store,
                                                final PromptBehavior promptBehavior) {
            logger.debug("Retrieving secret with key: {}, and prompt behavior: {}.", key, promptBehavior.name());

            E secret = null;
            if (promptBehavior != PromptBehavior.ALWAYS) {
                // Not ALWAYS prompt, so let's read from the store for any cached secret
                logger.debug("Reading secret from store for key: {}", key);
                secret = readFromStore(key, store);
            }

            if (promptBehavior == PromptBehavior.NEVER) {
                // NEVER prompt, return what we got from the store and call it done
                logger.debug("Returning whatever we retrieved from the store, do not prompt.");
                return secret;
            }

            if (promptBehavior == PromptBehavior.ALWAYS
                    || (secret == null && promptBehavior == PromptBehavior.AUTO)) {
                // Either ALWAYS prompt, or we don't have any secret cached for this key
                // AUTO-retrieves when necessary
                logger.debug("Retrieving secret.");
                secret = doRetrieve();

                // Store it so we don't have to retrieve again
                store(key, store, secret);
            }

            return secret;
        }
    }
}
