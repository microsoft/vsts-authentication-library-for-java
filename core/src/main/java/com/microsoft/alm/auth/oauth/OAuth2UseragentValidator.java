// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth.oauth;

import com.microsoft.alm.oauth2.useragent.Provider;
import com.microsoft.alm.oauth2.useragent.ProviderScanner;
import com.microsoft.alm.oauth2.useragent.UserAgentImpl;

/**
 * This class verifies the availability of OAuth2-useragent on the current platform
 */
public class OAuth2UseragentValidator {

    private final ProviderScanner scanner = new UserAgentImpl();

    /**
     * Determines if oauth2 useragent can be used on the current running system.
     *
     * @return {@code true} if oauth2-useragent can be used 100% positively
     *         {@code false} with any doubts
     */
    public boolean oauth2UserAgentAvailable() {
        // not tests are worthy adding since I don't control this implementation
        final Provider provider = scanner.findCompatibleProvider("JavaFx");

        // I only want JavaFx provider, don't want to use device profile provider while we still have SWT
        return provider != null && "JavaFx".equals(provider.getClassName());
    }
}
