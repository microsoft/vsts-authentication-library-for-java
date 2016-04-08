// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth.oauth.helpers;

import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.microsoftopentechnologies.auth.browser.BrowserLauncher;
import com.microsoftopentechnologies.auth.browser.BrowserLauncherHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

/**
 * This class extends the default BrowserLauncher provided by Microsoft Open Technologies and always launch
 * SWT browser outProc.
 *
 * If two intellij plugins try to load SWT browser, intellij hangs as two different plugin classloaders
 * will try to load the same native library provided by SWT.  Launch it out of proc in separate JVMs alleviate
 * this problem.
 */
public class MSOpenTechExternalBrowserLauncher implements BrowserLauncher {

    private static final Logger logger = LoggerFactory.getLogger(MSOpenTechExternalBrowserLauncher.class);

    public ListenableFuture<Void> browseAsync(final String url,
                                              final String redirectUrl,
                                              final String callbackUrl,
                                              final String windowTitle,
                                              final boolean noShell) {
        try {
            final File appJar = ADJarLoader.load();
            logger.debug("Loaded {}", appJar != null ? appJar.getAbsolutePath() : " none, failed to download swt jar.");
            BrowserLauncherHelper.launchExternalProcess(appJar, url, redirectUrl, callbackUrl, windowTitle, noShell);

            // Browser is started in a different process, nothing is blocked on current thread
            return Futures.immediateFuture(null);

        } catch (Throwable t) {
            return Futures.immediateFailedFuture(t);
        }
    }
}
