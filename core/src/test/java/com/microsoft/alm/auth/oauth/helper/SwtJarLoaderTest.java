// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth.oauth.helper;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class SwtJarLoaderTest {

    @Test
    public void testGetJarName() throws Exception {
        /**
         *this name should finally look like one of those:
         * org.eclipse.swt.cocoa.macosx.x86-4.4.2.jar
         * org.eclipse.swt.cocoa.macosx.x86_64-4.4.2.jar
         * org.eclipse.swt.gtk.linux.x86-4.4.2.jar
         * org.eclipse.swt.gtk.linux.x86_64-4.4.2.jar
         * org.eclipse.swt.win32.win32.x86-4.4.2.jar
         * org.eclipse.swt.win32.win32.x86_64-4.4.2.jar
         */
        final String mac64bit = SwtJarLoader.getJarName(false, false, true, true);
        isFilenameCorrect("org.eclipse.swt.cocoa.macosx.x86_64-4.4.2.jar", mac64bit);

        final String mac32bit = SwtJarLoader.getJarName(false, false, true, false);
        isFilenameCorrect("org.eclipse.swt.cocoa.macosx.x86-4.4.2.jar", mac32bit);

        final String linux64bit = SwtJarLoader.getJarName(false, true, false, true);
        isFilenameCorrect("org.eclipse.swt.gtk.linux.x86_64-4.4.2.jar", linux64bit);

        final String linux32bit = SwtJarLoader.getJarName(false, true, false, false);
        isFilenameCorrect("org.eclipse.swt.gtk.linux.x86-4.4.2.jar", linux32bit);

        final String win64bit = SwtJarLoader.getJarName(true, false, false, true);
        isFilenameCorrect("org.eclipse.swt.win32.win32.x86_64-4.4.2.jar", win64bit);

        final String win32bit = SwtJarLoader.getJarName(true, false, false, false);
        isFilenameCorrect("org.eclipse.swt.win32.win32.x86-4.4.2.jar", win32bit);
    }

    private void isFilenameCorrect(final String expected, final String actual) {
        assertEquals(expected, actual);
        assertNotNull(SwtJarLoader.CRC32_HASHES.get(actual));
    }

}