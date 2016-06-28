// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth.oauth.helper;

import org.junit.Test;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;

import static org.junit.Assert.assertTrue;

public class FileHashHelperTest {

    @Test(expected = IOException.class)
    public void calculateCRC32Hash_nonExistentFile() throws IOException {
        final File nonExistent = File.createTempFile("FileHashHelperTestCRC32", "unittest");
        nonExistent.delete();

        FileHashHelper.crc32Hash(nonExistent);
    }

    @Test(expected = IOException.class)
    public void calculateCRC32Hash_nullInputStream() throws IOException {
        FileHashHelper.crc32Hash((InputStream) null);
    }

    @Test
    public void calculateCRCHash() throws IOException {
        final File test = File.createTempFile("FileHashHelperTestCRC32", "unittest");
        final PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(test)));
        pw.print("This is a unit test");
        pw.close();

        long hash = FileHashHelper.crc32Hash(test);
        assertTrue(hash != 0);

        // I got this hash from my mac.  Make sure the same hash is calculated on different platforms
        assertTrue(hash == 3677983296L);

        System.out.println(hash);
    }
}