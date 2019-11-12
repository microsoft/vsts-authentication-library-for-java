// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.provider;

import com.microsoft.alm.common.secret.VsoTokenScope;

public class Options {

    /**
     * the only way to create this object is from the factory method
     * this guarantees every options has a patGenerationOptions object
     * no guarantee about the actual value inside the object though,
     * and they could be null
     */
    private Options(final String displayName, final VsoTokenScope scope) {
        // Right now only PAT requires any sort of options at all
        this.patGenerationOptions = new Options.PatGenerationOptions();
        this.patGenerationOptions.displayName = displayName;
        this.patGenerationOptions.tokenScope = scope;
    }

    public static Options getDefaultOptions() {
        final Options options = new Options("Personal Access Token", VsoTokenScope.AllScopes);

        return options;
    }

    public final PatGenerationOptions patGenerationOptions;

    public static class PatGenerationOptions {
        public String displayName;
        public VsoTokenScope tokenScope;
    }
}
