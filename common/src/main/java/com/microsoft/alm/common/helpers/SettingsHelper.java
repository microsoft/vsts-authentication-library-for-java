// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.common.helpers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Map;
import java.util.Properties;

/**
 * Utility class to read properties from a file.
 *
 * If the property is not found from the setting file, it will fallback to System properties.
 */
public class SettingsHelper {

    private static final Logger logger = LoggerFactory.getLogger(SettingsHelper.class);

    private static final String VENDOR_FOLDER = SystemHelper.isLinux() ? ".microsoft" : "Microsoft";
    private static final String PROGRAM_FOLDER = "VstsAuthLib4J";
    private static final String FILE_NAME = "settings.properties";

    private final Properties properties = new Properties();

    private static final String DO_NOT_SET_SYSTEM_ENV = "doNotSetSystemEnv";

    private static SettingsHelper instance;

    public static synchronized SettingsHelper getInstance() {
        if (instance == null) {
            instance = new SettingsHelper();
        }

        return instance;
    }

    private static String getSettingsFolderName() {
        final String folder;
        if (SystemHelper.isWindows()) {
            folder = Path.construct(Environment.getFolderPath(Environment.SpecialFolder.LocalApplicationData),
                        VENDOR_FOLDER,
                        PROGRAM_FOLDER);

        } else if (SystemHelper.isMac()) {
            folder = Path.construct(Environment.getFolderPath(Environment.SpecialFolder.UserProfile),
                        "Library",
                        "Application Support",
                        VENDOR_FOLDER,
                        PROGRAM_FOLDER);
        } else {
            folder = Path.construct(Environment.getFolderPath(Environment.SpecialFolder.UserProfile),
                        VENDOR_FOLDER,
                        PROGRAM_FOLDER);

        }

        return folder;
    }

    private SettingsHelper() {
        final String path = getSettingsFolderName();
        final File folder = new File(path);
        logger.info("Searching for {}", Path.combine(folder.getAbsolutePath(), FILE_NAME));
        if (folder.exists()) {
            final File potential = new File(folder, FILE_NAME);
            if (potential.exists() && potential.isFile() && potential.canRead()) {
                logger.info("Found setting file, trying to load properties from {}", potential.getAbsolutePath());

                try {
                    properties.load(new FileReader(potential));
                    logger.info("Properties loaded.");
                    final boolean setSystemEnv = !(Boolean.valueOf(properties.getProperty(DO_NOT_SET_SYSTEM_ENV)));
                    if (setSystemEnv) {
                        // oauth2-useragent reads System properties.  If we want to propagate any values downstream,
                        // we must load our properties into System.properties
                        for (final Map.Entry<Object, Object> entry : properties.entrySet()) {
                            if (entry.getKey() instanceof String && entry.getValue() instanceof String) {
                                logger.info("Setting System property {} to {}", entry.getKey(), entry.getValue());
                                System.setProperty(entry.getKey().toString(), entry.getValue().toString());
                            }
                        }
                    }
                } catch (Throwable t) {
                    logger.warn("Failed to load properties.", t);
                    properties.clear();
                }
            }
        }
    }

    /**
     * Get named property.  Values from the setting files take precedence over System properties.
     * The method returns {@code null} if the property is not defined.
     *
     * @param name Property name
     * @return value of the property. {@code null} if property is not defined.
     */
    public synchronized String getProperty(final String name) {
        String result = properties.getProperty(name);
        if (result == null) {
            result = System.getProperty(name);
        }

        return result;
    }


    /**
     * Get named property.  Values from the setting files take precedence over System properties.
     *
     * If the property is not defined, return the default value.
     *
     * @param name Property name
     * @param defaultValue This value will be returned if property is not defined
     * @return value of the property, or the defaultValue.
     */
    public synchronized String getProperty(final String name, final String defaultValue) {
        final String result = getProperty(name);
        return result == null ? defaultValue : result;
    }
}
