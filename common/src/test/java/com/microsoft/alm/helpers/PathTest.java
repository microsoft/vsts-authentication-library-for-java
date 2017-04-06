// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.helpers;

import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class PathTest {
    @Test
    public void changeExtension_single() {
        final String goodFileName = "C:\\mydir\\myfile.com";

        final String actual = Path.changeExtension(goodFileName, ".old");

        Assert.assertEquals("C:\\mydir\\myfile.old", actual);
    }

    @Test
    public void changeExtension_singleWithoutLeadingPeriod() {
        final String goodFileName = "C:\\mydir\\myfile.com";

        final String actual = Path.changeExtension(goodFileName, "old");

        Assert.assertEquals("C:\\mydir\\myfile.old", actual);
    }

    @Test
    public void changeExtension_multiple() {
        final String goodFileName = "C:\\mydir\\myfile.com.extension";

        final String actual = Path.changeExtension(goodFileName, ".old");

        Assert.assertEquals("C:\\mydir\\myfile.com.old", actual);
    }

    @Test
    public void changeExtension_badFileName() {
        final String badFileName = "C:\\mydir\\";

        final String actual = Path.changeExtension(badFileName, ".old");

        Assert.assertEquals("C:\\mydir\\.old", actual);
    }

    // If extension is null, the returned string contains the contents of path
    // with the last period and all characters following it removed.
    @Test
    public void changeExtension_nullExtensionRemovesIt() {
        final String goodFileName = "C:\\mydir\\myfile.com.extension";

        final String actual = Path.changeExtension(goodFileName, null);

        Assert.assertEquals("C:\\mydir\\myfile.com", actual);
    }

    // If extension is an empty string, the returned path string contains the contents of path
    // with any characters following the last period removed.
    @Test
    public void changeExtension_emptyExtensionRemovesIt() {
        final String goodFileName = "C:\\mydir\\myfile.com.extension";

        final String actual = Path.changeExtension(goodFileName, StringHelper.Empty);

        Assert.assertEquals("C:\\mydir\\myfile.com.", actual);
    }

    @Test
    public void construct_path() {
        final String[] goodSegments = new String[]{"Library", "Application Support", "Microsoft"};

        final String actual = Path.construct(goodSegments);

        Assert.assertEquals("Library" + File.separator
                + "Application Support" + File.separator + "Microsoft", actual);
    }

    @Test
    public void construct_argspath() {
        final String actual = Path.construct("Library", "Application Support", "Microsoft");

        Assert.assertEquals("Library" + File.separator
                + "Application Support" + File.separator + "Microsoft", actual);
    }

    @Test
    public void construct_emptypath() {
        final String[] emptySegments = new String[0];

        String actual = Path.construct(emptySegments);

        Assert.assertEquals("", actual);

        final List<String> emptyLists = new ArrayList<String>();

        actual = Path.construct(emptyLists.toArray(new String[0]));

        Assert.assertEquals("", actual);
    }
}
