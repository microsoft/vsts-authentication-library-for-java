// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.storage.posix.internal;

import com.microsoft.alm.helpers.Debug;
import com.microsoft.alm.helpers.SystemHelper;
import com.microsoft.alm.secret.Secret;
import com.microsoft.alm.storage.SecretStore;
import com.sun.jna.Pointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class GnomeKeyringBackedSecureStore<E extends Secret> implements SecretStore<E> {

    private static final Logger logger = LoggerFactory.getLogger(GnomeKeyringBackedSecureStore.class);

    private static final GnomeKeyringLibrary INSTANCE = getGnomeKeyringLibrary();
    private static final GnomeKeyringLibrary.GnomeKeyringPasswordSchema SCHEMA = getGnomeKeyringPasswordSchema();


    /**
     * Create a {@code Secret} from the stored string representation
     *
     * @param secret password, oauth2 access token, or Personal Access Token
     * @return a {@code Secret} from the input
     */
    protected abstract E deserialize(final String secret);

    /**
     * Create a string representation suitable to be saved as String
     *
     * @param secret password, oauth2 access token, or Personal Access Token
     * @return a string representation of the secret
     */
    protected abstract String serialize(final E secret);

    /**
     * Return the type of this securestore, used to match the secret in gnome-keyring
     *
     * @return type string representation of the secret type
     */
    protected abstract String getType();

    /**
     * Read a secret from gnome-keyring using its simple password API
     *
     * @param key for which a secret is associated with
     * @return secret
     */
    @Override
    public E get(final String key) {
        Debug.Assert(key != null, "key cannot be null");

        logger.info("Getting {} for {}", getType(), key);

        GnomeKeyringLibrary.PointerToPointer pPassword = new GnomeKeyringLibrary.PointerToPointer();
        String secret = null;
        try {
            int result = -1;
            synchronized (INSTANCE) {
                result = INSTANCE.gnome_keyring_find_password_sync(
                        SCHEMA,
                        pPassword,
                        "Type", getType(),
                        "Key", key,
                        null);
            }

            if (result == GnomeKeyringLibrary.GNOME_KEYRING_RESULT_OK) {
                secret = pPassword.pointer.getString(0);
            }

        } finally {
            if (pPassword.pointer != null) {
                synchronized (INSTANCE) {
                    INSTANCE.gnome_keyring_free_password(pPassword.pointer);
                }
            }
        }

        return secret != null ? deserialize(secret) : null;
    }

    @Override
    public boolean delete(final String key) {
        Debug.Assert(key != null, "key cannot be null");
        logger.info("Deleting {} for {}", getType(), key);

        synchronized (INSTANCE) {
            int result = INSTANCE.gnome_keyring_delete_password_sync(
                    SCHEMA,
                    "Type", getType(),
                    "Key", key,
                    null);

            return result == GnomeKeyringLibrary.GNOME_KEYRING_RESULT_OK;
        }
    }

    @Override
    public boolean add(final String key, E secret) {
        Debug.Assert(key != null, "key cannot be null");
        Debug.Assert(secret != null, "Secret cannot be null");

        logger.info("Adding a {} for {}", getType(), key);

        synchronized (INSTANCE) {
            int result = INSTANCE.gnome_keyring_store_password_sync(
                    SCHEMA,
                    GnomeKeyringLibrary.GNOME_KEYRING_DEFAULT, // save to disk
                    "Microsoft authentication data for Visual Studio Team Services", //display name
                    serialize(secret),
                    //attributes list
                    "Type", getType(),
                    "Key", key,
                    null
            );

            return result == GnomeKeyringLibrary.GNOME_KEYRING_RESULT_OK;
        }
    }

    /**
     * Gnome-keyring is considered secure
     *
     * @return {@code true} for gnome-keyring
     */
    @Override
    public boolean isSecure() {
        return true;
    }

    /**
     * Check for gnome-keyring suppport on this platform
     *
     * @return {@code true} if gnome-keyring library is available; {$code false} otherwise
     */
    public static boolean isGnomeKeyringSupported() {
        if (INSTANCE != null && SCHEMA != null) {
            try {
                GnomeKeyringLibrary.PointerToPointer pPassword = new GnomeKeyringLibrary.PointerToPointer();
                INSTANCE.gnome_keyring_find_password_sync(SCHEMA,
                        pPassword,
                        // The following two value should not match anything, calling this method purely
                        // to determine existence of this function since we have no version information
                        "Type", "NullType",
                        "Key", "NullKey",
                        null
                        );

                return true;

            } catch (UnsatisfiedLinkError error) {
                logger.warn("Gnome-keyring on this platform does not support the simple password API.  " +
                        "We require gnome-keyring 2.12+.");
            }
        }

        return false;
    }

    private static boolean isGnomeKeyringLibraryAvaialble() {
        if (SystemHelper.isLinux()) {
            try {
                // First make sure gnome-keyring library exists
                GnomeKeyringLibrary gnomeKeyringLibrary = GnomeKeyringLibrary.INSTANCE;

                return true;
            } catch (UnsatisfiedLinkError error) {
                // ignore error
                logger.debug("Gnome keyring library not present", error);
            }
        }

        return false;
    }

    private static GnomeKeyringLibrary getGnomeKeyringLibrary() {
        if (isGnomeKeyringLibraryAvaialble()) {
            return GnomeKeyringLibrary.INSTANCE;
        } else {
            logger.warn("Gnome keyring library not present, returning a dummy library.  " +
                    "This is a bug unless you are testing");

            // on platform that doesn't suport gnome keyring, just return a dummy
            return new GnomeKeyringLibrary() {
                @Override
                public int gnome_keyring_store_password_sync(GnomeKeyringPasswordSchema schema, String keyring, String display_name, String password, Object... args) {
                    return -1;
                }

                @Override
                public int gnome_keyring_find_password_sync(GnomeKeyringPasswordSchema schema, PointerToPointer pPassword, Object... args) {
                    return -1;
                }

                @Override
                public int gnome_keyring_delete_password_sync(GnomeKeyringPasswordSchema schema, Object... args) {
                    return -1;
                }

                @Override
                public void gnome_keyring_free_password(Pointer password) {

                }
            };
        }
    }

    private static GnomeKeyringLibrary.GnomeKeyringPasswordSchema getGnomeKeyringPasswordSchema() {
        if (isGnomeKeyringLibraryAvaialble()) {
            logger.debug("Gnome keyring is supported, return a password SCHEMA");
            GnomeKeyringLibrary.GnomeKeyringPasswordSchema schema
                    = new GnomeKeyringLibrary.GnomeKeyringPasswordSchema();

            schema.item_type = GnomeKeyringLibrary.GNOME_KEYRING_ITEM_GENERIC_SECRET;
            //Type and Key, all fields are strings
            schema.attributes = new GnomeKeyringLibrary.GnomeKeyringPasswordSchemaAttribute[3];
            schema.attributes[0] = new GnomeKeyringLibrary.GnomeKeyringPasswordSchemaAttribute();
            schema.attributes[0].name = "Type";
            schema.attributes[0].type = GnomeKeyringLibrary.GNOME_KEYRING_ATTRIBUTE_TYPE_STRING;

            schema.attributes[1] = new GnomeKeyringLibrary.GnomeKeyringPasswordSchemaAttribute();
            schema.attributes[1].name = "Key";
            schema.attributes[1].type = GnomeKeyringLibrary.GNOME_KEYRING_ATTRIBUTE_TYPE_STRING;

            // Terminating
            schema.attributes[2] = new GnomeKeyringLibrary.GnomeKeyringPasswordSchemaAttribute();
            schema.attributes[2].name = null;
            schema.attributes[2].type = 0;

            return schema;
        }

        logger.debug("Gnome keyring is NOT supported, return null for SCHEMA");
        return null;
    }
}
