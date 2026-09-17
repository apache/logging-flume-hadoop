/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.flume.configfilter;

import static org.apache.flume.configfilter.HadoopCredentialStoreConfigFilter.CREDENTIAL_PROVIDER_PATH;
import static org.apache.flume.configfilter.HadoopCredentialStoreConfigFilter.HADOOP_SECURITY;
import static org.apache.flume.configfilter.HadoopCredentialStoreConfigFilter.PASSWORD_FILE_CONFIG_KEY;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeFalse;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.HashMap;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.alias.CredentialShell;
import org.apache.hadoop.util.ToolRunner;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

public class TestHadoopCredentialStoreConfigFilter {

    private static String providerPathDefault;
    private static String providerPathEnv;
    private static String providerPathPwdFile;

    @ClassRule
    public static final EnvironmentVariables environmentVariables = new EnvironmentVariables();

    private static File fileDefault;
    private static File fileEnvPassword;
    private static File fileFilePassword;
    private HadoopCredentialStoreConfigFilter configFilter;

    @BeforeClass
    public static void setUpClass() throws Exception {
        // Hadoop's keystore providers read and set file permissions through `winutils.exe` on Windows,
        // which is not available on the CI runners.
        assumeFalse(
                "Hadoop's keystore providers need winutils on Windows",
                System.getProperty("os.name").startsWith("Windows"));
        generateTempFileNames();
        fillCredStoreWithDefaultPassword();
        fillCredStoreWithPasswordFile();
        fillCredStoreWithEnvironmentVariablePassword();
    }

    @Before
    public void setUp() {
        String[] objects = System.getenv().keySet().toArray(new String[0]);
        environmentVariables.clear(objects);
        configFilter = new HadoopCredentialStoreConfigFilter();
    }

    @Test
    public void filterDefaultPasswordFile() {
        HashMap<String, String> configuration = new HashMap<>();
        configuration.put(CREDENTIAL_PROVIDER_PATH, providerPathDefault);
        configFilter.initializeWithConfiguration(configuration);

        assertEquals("filtered_default", configFilter.filter("password"));
    }

    @Test
    public void filterWithEnvPassword() {
        environmentVariables.set("HADOOP_CREDSTORE_PASSWORD", "envSecret");
        HashMap<String, String> configuration = new HashMap<>();
        configuration.put(CREDENTIAL_PROVIDER_PATH, providerPathEnv);
        configFilter.initializeWithConfiguration(configuration);

        assertEquals("filtered_env", configFilter.filter("password"));
    }

    @Test
    public void filterWithPasswordFile() {
        HashMap<String, String> configuration = new HashMap<>();
        configuration.put(CREDENTIAL_PROVIDER_PATH, providerPathPwdFile);
        configuration.put(PASSWORD_FILE_CONFIG_KEY, "test-password.txt");
        configFilter.initializeWithConfiguration(configuration);

        assertEquals("filtered_file", configFilter.filter("password"));
    }

    @Test
    public void filterWithEnvNoPassword() {
        HashMap<String, String> configuration = new HashMap<>();
        configuration.put(CREDENTIAL_PROVIDER_PATH, providerPathEnv);
        configFilter.initializeWithConfiguration(configuration);

        assertNull(configFilter.filter("password"));
    }

    @Test
    public void filterErrorWithPasswordFileWrongPassword() {
        HashMap<String, String> configuration = new HashMap<>();
        configuration.put(CREDENTIAL_PROVIDER_PATH, providerPathPwdFile);
        configuration.put(PASSWORD_FILE_CONFIG_KEY, "test-password2.txt");
        configFilter.initializeWithConfiguration(configuration);

        assertNull(configFilter.filter("password"));
    }

    @Test
    public void filterErrorWithPasswordFileNoPasswordFile() {
        HashMap<String, String> configuration = new HashMap<>();
        configuration.put(CREDENTIAL_PROVIDER_PATH, providerPathPwdFile);
        configFilter.initializeWithConfiguration(configuration);

        assertNull(configFilter.filter("password"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void filterErrorWithNoProvider() {
        HashMap<String, String> configuration = new HashMap<>();
        configFilter.initializeWithConfiguration(configuration);
    }

    private static void fillCredStoreWithEnvironmentVariablePassword() throws Exception {
        environmentVariables.set("HADOOP_CREDSTORE_PASSWORD", "envSecret");

        runCommand("create password -value filtered_env -provider " + providerPathEnv, new Configuration());
    }

    private static void fillCredStoreWithPasswordFile() throws Exception {
        Configuration conf = new Configuration();
        conf.set(HADOOP_SECURITY + PASSWORD_FILE_CONFIG_KEY, "test-password.txt");
        runCommand("create password -value filtered_file -provider " + providerPathPwdFile, conf);
    }

    private static void fillCredStoreWithDefaultPassword() throws Exception {
        runCommand("create password -value filtered_default -provider " + providerPathDefault, new Configuration());
    }

    private static void generateTempFileNames() throws IOException {
        fileDefault = createTempFileName("test-default-pwd-");
        fileEnvPassword = createTempFileName("test-env-pwd-");
        fileFilePassword = createTempFileName("test-file-pwd-");

        // Build the provider path from a `file:` URI, so that Windows paths are encoded correctly.
        providerPathDefault = "jceks://file" + fileDefault.toURI().getRawPath();
        providerPathEnv = "jceks://file" + fileEnvPassword.toURI().getRawPath();
        providerPathPwdFile = "jceks://file" + fileFilePassword.toURI().getRawPath();
    }

    /**
     * Reserves a temporary file name for a keystore, which the credential provider creates itself.
     */
    private static File createTempFileName(String prefix) throws IOException {
        File file = Files.createTempFile(prefix, ".jceks").toFile();
        // Delete the keystore created by the credential provider at the end of the tests.
        file.deleteOnExit();
        if (!file.delete()) {
            fail("Could not delete temporary file " + file);
        }
        return file;
    }

    private static void runCommand(String c, Configuration conf) throws Exception {
        ToolRunner.run(conf, new CredentialShell(), c.split(" "));
    }
}
