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
     * Check if it is running on Windows
     *
     * @return
     *      true if running on Windows; false otherwise
     */
    public static boolean isWindows() {
        return Provider.isWindows(osName);
    }

    /**
     * Check if it is running on Linux 
     *
     * @return
     *      true if running on Windows; false otherwise
     */
    public static boolean isLinux() {
        return Provider.isLinux(osName);
    }
}
