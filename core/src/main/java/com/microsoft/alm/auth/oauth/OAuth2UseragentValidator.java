// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth.oauth;

import com.microsoft.alm.oauth2.useragent.Provider;

import java.util.Collections;
import java.util.List;

/**
 * This class verifies the availability of OAuth2-useragent on the current platform
 *
 * This is a interim class that will go away once we merge
 * https://github.com/Microsoft/oauth2-useragent/pull/21
 */
public class OAuth2UseragentValidator {

    // This is a hack since it depends on oauth2-useragent implementations
    // This should be removed as soon as the pull request mentioned is merged
    private static final Provider provider = new Provider("OAuth2UseragentValidator") {
        @Override
        public List<String> checkRequirements() {
            return Collections.<String>emptyList();
        }

        @Override
        public void augmentProcessParameters(List<String> list, List<String> list1) { }
    };

    /**
     * Determines if oauth2 useragent can be used on the current running system.
     *
     * Except we don't have for desktop environment -- plugin should guarantee a desktop
     * environment is available.
     *
     * Be conservative, could return false negative.
     *
     * @return {@code true} if oauth2-useragent can be used 100% positively
     *         {@code false} with any doubts
     */
    public static boolean oauth2UserAgentAvailable() {
        // not tests are worthy adding since I don't control this implementation
        final List<String> javaFxRequirements = provider.JAVA_FX.checkRequirements();

        return javaFxRequirements.isEmpty();
    }
}
