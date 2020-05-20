// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth.oauth.helper;

import com.microsoft.alm.common.helpers.IOHelper;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.CRC32;

/**
 * Utility to calculate File hashes.
 */
public class FileHashHelper {

    /**
     * Calculates CRC32 hash of a given file.
     *
     * Warning: CRC32 is not a secure hash algorithm.
     *
     * @param f any file
     * @return CRC32 hash of the file
     * @throws IOException
     */
    public static long crc32Hash(final File f) throws IOException {
        if (!f.isFile()) {
            throw new IOException(f.getAbsolutePath() + " is not a valid file.");
        }

        final FileInputStream fis = new FileInputStream(f);
        final long hash = crc32Hash(fis);
        IOHelper.closeQuietly(fis);

        return hash;
    }

    /**
     * Calculate CRC32 hash of a given input stream.
     *
     * Warning: CRC32 is not a secure hash algorithm.
     *
     * @param is a stream of bytes
     * @return CRC32 hash of this stream
     * @throws IOException
     */
    public static long crc32Hash(final InputStream is) throws IOException {
        if (is == null) {
            throw new IOException("InputStream is null.");
        }

        final CRC32 crcMaker = new CRC32();
        final byte[] buffer = new byte[65536];
        int bytesRead;
        while((bytesRead = is.read(buffer)) != -1) {
            crcMaker.update(buffer, 0, bytesRead);
        }

        return crcMaker.getValue();
    }
}
