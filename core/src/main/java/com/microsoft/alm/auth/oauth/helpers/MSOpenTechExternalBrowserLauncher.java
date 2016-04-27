// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth.oauth.helpers;

import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.microsoft.alm.oauth2.useragent.AuthorizationException;
import com.microsoft.alm.oauth2.useragent.AuthorizationResponse;
import com.microsoft.alm.oauth2.useragent.subprocess.DefaultProcessFactory;
import com.microsoft.alm.oauth2.useragent.subprocess.ProcessCoordinator;
import com.microsoft.alm.oauth2.useragent.subprocess.TestableProcess;
import com.microsoft.alm.oauth2.useragent.subprocess.TestableProcessFactory;
import com.microsoftopentechnologies.auth.browser.BrowserLauncher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

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
            launchExternalProcess(appJar, url, redirectUrl, callbackUrl, windowTitle, noShell);

            // Browser is started in a different process, nothing is blocked on current thread
            return Futures.immediateFuture(null);

        } catch (Throwable t) {
            return Futures.immediateFailedFuture(t);
        }
    }

    private static void launchExternalProcess(final File appJar,
                                              final String url,
                                              final String redirectUrl,
                                              final String callbackUrl,
                                              final String windowTitle,
                                              final boolean noShell) throws AuthorizationException {
        final List<String> args = new ArrayList<String>();
        final File javaHome = new File(System.getProperty("java.home"));
        final File javaExecutable = new File(javaHome, "bin" + File.separator + "java");
        args.add(javaExecutable.getAbsolutePath());
        final boolean isMac = System.getProperty("os.name").toLowerCase().contains("mac");
        if(isMac) {
            args.add("-XstartOnFirstThread");
        }

        // relay network properties
        addSWTNetworkProxyOptions(args);

        // relay all swt browser settings
        addSWTBrowserOptions(args);

        args.add("-cp");
        args.add(appJar.getAbsolutePath());
        args.add("com.microsoftopentechnologies.adinteractiveauth.Program");
        args.add(url);
        args.add(redirectUrl);
        args.add(callbackUrl);
        args.add(windowTitle);
        args.add("true");
        args.add(String.valueOf(noShell));

        try {
            final TestableProcessFactory processFactory = new DefaultProcessFactory();
            final TestableProcess process = processFactory.create(args.toArray(new String[args.size()]));
            final ProcessCoordinator coordinator = new ProcessCoordinator(process);
            final int retCode = coordinator.waitFor();

            final String response = coordinator.getStdOut();
            final String errorContents = coordinator.getStdErr();

            logger.info("return code from SWT window subprocess: {}", retCode);
            logger.debug("stdout from swt window: {}", response);
            logger.warn("stderr from swt window: {}", errorContents);

            if (retCode != 0) {
                // SWT browser closed unexpectedly, we need to notify the web server that is waiting for the data
                httpRequest(new URL(callbackUrl + "?" +
                        URLEncoder.encode(String.format("status=failed&%s", errorContents), "UTF-8")));
            }
        }
        catch (final Exception e) {
            throw new AuthorizationException("exception", e.getMessage(), null, e);
        }
    }

    private static void addSWTNetworkProxyOptions(final List<String> args) {
        //key names are taken from www.eclipse.org/swt/faq.php#browserproxy
        final String proxyHostKey = "network.proxy_host";
        final String proxyPortKey = "network.proxy_port";

        String proxyHostValue = System.getProperty(proxyHostKey);
        if (proxyHostValue == null) {
            // network.proxy_host is not set specifically, check standard java proxy settings and relay that
            proxyHostValue = System.getProperty("http.proxyHost");
        }
        if (proxyHostValue != null) {
            addProperty(proxyHostKey, proxyHostValue, args);
        }

        String proxyPortValue = System.getProperty(proxyPortKey);
        if (proxyPortValue == null) {
            // network.proxy_port is not set specifically, check standard java proxy settings and relay that
            proxyPortValue = System.getProperty("http.proxyPort");
        }
        if (proxyPortValue != null) {
            addProperty(proxyPortKey, proxyPortValue, args);
        }
    }

    private static void addSWTBrowserOptions(final List<String> args) {
        final Properties properties = System.getProperties();
        for (final String propName : properties.stringPropertyNames()) {
            if (propName.startsWith("org.eclipse.swt.browser"))  {
                final String propValue = properties.getProperty(propName);
                if (propValue != null) {
                    addProperty(propName, propValue, args);
                }
            }
        }
    }

    private static void addProperty(final String propName, final String propValue, final List<String> args) {
        final String prop = String.format("-D%s=%s", propName, propValue);
        logger.debug("Adding {} to swt process.", prop);
        args.add(prop);
    }

    private static void httpRequest(final URL url) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.getResponseCode();
    }
}
