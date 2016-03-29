// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.helpers;

import com.microsoft.alm.oauth2.useragent.Provider;

/**
 * System utilities
 */
public class SystemHelper {

    final static String osName = System.getProperty("os.name");

    /**
     * Check if the process is running on Windows platform
     *
     * @return
     *      {@code true} if running on Windows; {@code false} otherwise
     */
    public static boolean isWindows() {
        return Provider.isWindows(osName);
    }

    /**
     * Check if it is running on Linux 
     *
     * @return
     *      {@code true} if running on Linux; {@code false} otherwise
     */
    public static boolean isLinux() {
        return Provider.isLinux(osName);
    }

    /**
     * Check if it is running on Mac OSX
     *
     * @return
     *      {@code true} if running on Linux; {@code false} otherwise
     */
    public static boolean isMac() {
        return Provider.isMac(osName);
    }
}
