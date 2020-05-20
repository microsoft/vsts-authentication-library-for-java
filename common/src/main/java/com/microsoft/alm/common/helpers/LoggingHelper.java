// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.common.helpers;

import org.slf4j.Logger;

public class LoggingHelper {

    /**
     * IntelliJ bubbles up all error level logging to user, and if there is a "cause", it makes it a clickable link
     * and user can view the stacktrace.
     *
     * However, IntelliJ also exposes an button to disable this plugin on the stacktrace viewer, which is not
     * desirable, so in this case we just log the error message, but show the cause in a warning log
     *
     * @param logger the logger to use
     * @param message the message to display
     * @param cause the chained exception
     */
    public static void logError(final Logger logger , final String message, final Throwable cause) {
        logger.error(message);
        //weird thing we are doing for IntelliJ
        logger.warn(message, cause);
    }
}
