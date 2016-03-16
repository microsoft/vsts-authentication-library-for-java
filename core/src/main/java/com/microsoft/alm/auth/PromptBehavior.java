// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth;

/**
 * Indicates whether this library should automatically prompt only if necessary or whether
 * it should prompt regardless of whether there is a cached token.
 */
public enum PromptBehavior {
    /**
     * Will prompt the user for credentials only when necessary.  If a token
     * that meets the requirements is already cached then the user will not be prompted.
     *
     * We do not check for scope requirement, so you may get a token that has different scope from what you specified.
     */
    AUTO,

    /**
     * The user will be prompted for credentials even if there is a token that meets the requirements
     * already in the cache.
     */
    ALWAYS,

    /**
     * The user will not be prompted for credentials.  If prompting is necessary then the request to get a secret
     * will fail.
     */
    NEVER
}
