// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth.oauth.helpers;

import com.microsoftopentechnologies.auth.FileCache;
import com.microsoftopentechnologies.auth.FileSource;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.concurrent.ExecutionException;


/**
 *  Copied from:
 *  https://github.com/MSOpenTech/azure-activedirectory-interactive-auth-library-for-java/blob/master/src/com/microsoftopentechnologies/auth/ADJarLoader.java
 *
 *  Modified the base url to point to our blob storage only
 */
public class ADJarLoader {
    private static final String BASE_URL = "https://az771546.vo.msecnd.net/swt-binary-for-auth-library/";
    private static FileCache filesCache;
    private static String jarName;

    static {
        String osName = System.getProperty("os.name").toLowerCase();
        boolean isWindows = osName.contains("win");
        boolean isMac = osName.contains("mac");
        boolean isLinux = osName.contains("linux");
        boolean isx64 = System.getProperty("os.arch").contains("64");

        // this name should finally look something like this:
        //  ad-interactive-auth-linux-x64.jar
        jarName = "ad-interactive-auth-" +
                (isWindows ? "win32-" :
                        isMac ? "osx-" :
                                isLinux ? "linux-" : "") +
                (isx64 ? "x64" : "x86") +
                ".jar";
    }

    public static File load() throws ExecutionException, MalformedURLException {
        if(filesCache == null) {
            filesCache = new FileCache(new FileSource[] {
                    new FileSource(jarName, new URL(BASE_URL + jarName))
            });
        }

        return filesCache.getFile(jarName);
    }
}
