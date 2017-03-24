// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth.oauth.helper;

import com.microsoft.alm.helpers.IOHelper;
import com.microsoft.alm.helpers.SystemHelper;
import com.microsoft.alm.oauth2.useragent.StandardWidgetToolkitProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

public class SwtJarLoader {
    private static final Logger logger = LoggerFactory.getLogger(SwtJarLoader.class);

    private static final String BASE_URL = "https://az771546.vo.msecnd.net/swt-binary-for-auth-library/";

    private static String jarName;
    private static File targetSwtJar;

    private static String SWT_VERSION="4.4.2";

    static final Map<String, Long> CRC32_HASHES;

    static {
        boolean isWindows = SystemHelper.isWindows();
        boolean isMac = SystemHelper.isMac();
        boolean isLinux = SystemHelper.isLinux();

        boolean isx64 = System.getProperty("os.arch").contains("64");

        jarName = getJarName(isWindows, isLinux, isMac, isx64);

        targetSwtJar = new File(StandardWidgetToolkitProvider.getDefaultSwtJarPath());

        Map<String, Long> hashes = new HashMap<String, Long>();

        //CRC32 Hashes of 4.4.2 SWT jar
        hashes.put("org.eclipse.swt.cocoa.macosx.x86-4.4.2.jar", 2804720395L);
        hashes.put("org.eclipse.swt.cocoa.macosx.x86_64-4.4.2.jar", 3069467037L);
        hashes.put("org.eclipse.swt.gtk.linux.x86-4.4.2.jar", 466147888L);
        hashes.put("org.eclipse.swt.gtk.linux.x86_64-4.4.2.jar", 3777958147L);
        hashes.put("org.eclipse.swt.win32.win32.x86-4.4.2.jar", 2366837566L);
        hashes.put("org.eclipse.swt.win32.win32.x86_64-4.4.2.jar", 3238843570L);

        CRC32_HASHES = Collections.unmodifiableMap(hashes);
    }

    static String getJarName(final boolean isWindows, final boolean isLinux, final boolean isMac, final boolean isx64) {
        /**
         *this name should finally look like one of those:
         * org.eclipse.swt.cocoa.macosx.x86-4.4.2.jar
         * org.eclipse.swt.cocoa.macosx.x86_64-4.4.2.jar
         * org.eclipse.swt.gtk.linux.x86-4.4.2.jar
         * org.eclipse.swt.gtk.linux.x86_64-4.4.2.jar
         * org.eclipse.swt.win32.win32.x86-4.4.2.jar
         * org.eclipse.swt.win32.win32.x86_64-4.4.2.jar
         */
        final String jarName = "org.eclipse.swt." +
                (isWindows ? "win32.win32" :
                        isMac ? "cocoa.macosx" :
                                isLinux ? "gtk.linux" : "") +
                (isx64 ? ".x86_64-" : ".x86-") +
                SWT_VERSION +
                ".jar";

        return jarName;
    }

    public static boolean tryGetSwtJar(final AtomicReference<File> swtJarReference) {
        //precondition: swt runtime jar is not present on the system
        final String swtJarUrl = BASE_URL + jarName;
        logger.info("Downloading {}", swtJarUrl);

        try {
            final HttpURLConnection cloudSwtUrlConn = (HttpURLConnection) new URL(swtJarUrl).openConnection();
            final int statusCode = cloudSwtUrlConn.getResponseCode();
            if (statusCode != 200) {
                throw new IOException(String.format("Failed to download SWT Runtime jar from %s.  Server return code is " +
                        "%d", swtJarUrl, statusCode));
            }

            // Make sure the parent folder exists
            final File parent = targetSwtJar.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }

            targetSwtJar.createNewFile();
            final FileOutputStream fos = new FileOutputStream(targetSwtJar);
            final InputStream is = cloudSwtUrlConn.getInputStream();

            IOHelper.copyStream(is, fos);

            IOHelper.closeQuietly(is);
            IOHelper.closeQuietly(fos);

            if (isValid(targetSwtJar)) {
                swtJarReference.set(targetSwtJar);
                return true;
            } else {
                // if target jar is corrupted, cleanup
                cleanup(targetSwtJar);
            }

        } catch (IOException ioe) {
            logger.warn("Failed to download SWT Runtime jar.", ioe);
            // if we failed during downloading, remove partial file
            cleanup(targetSwtJar);
        }

        swtJarReference.set(null);
        return false;
    }

    private static void cleanup(final File target) {
        if(target.exists()) {
            target.delete();
        }
    }

    private static boolean isValid(final File swtJar) {
        try {
            long hash = CRC32_HASHES.get(jarName);

            // This only checks the file exists, and assert download didn't corrupt the file.
            return swtJar.isFile() && FileHashHelper.crc32Hash(swtJar) == hash;
        } catch (IOException e) {
            logger.error("Failed to calculate CRC32 Hash of {}", swtJar, e);
        }

        return false;
    }

}
