// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.common.storage;

import com.microsoft.alm.common.storage.InsecureFileBackend;
import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.io.IOException;

public class InsecureFileBackendIT {

    @Test
    public void reload_emptyFile() throws IOException {
        File tempFile = null;
        try {
            tempFile = File.createTempFile(this.getClass().getSimpleName(), null);
            Assert.assertEquals(0L, tempFile.length());

            final InsecureFileBackend cut = new InsecureFileBackend(tempFile);

            Assert.assertEquals(0, cut.Tokens.size());
            Assert.assertEquals(0, cut.Credentials.size());
        } finally {
            if (tempFile != null)
                tempFile.delete();
        }
    }

    @Test
    public void save_toFile() throws IOException {
        File tempFile = null;
        try {
            tempFile = File.createTempFile(this.getClass().getSimpleName(), null);
            final InsecureFileBackend cut = new InsecureFileBackend(tempFile);

            cut.save();

            Assert.assertTrue(tempFile.length() > 0);
        } finally {
            if (tempFile != null)
                tempFile.delete();
        }
    }

}