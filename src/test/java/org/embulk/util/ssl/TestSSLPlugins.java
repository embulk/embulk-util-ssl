/*
 * Copyright 2015 The Embulk project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.embulk.util.ssl;

import org.embulk.util.ssl.SSLPlugins.SSLPluginConfig;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.UncheckedIOException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class TestSSLPlugins
{
    private static final String FTP_TEST_SSL_TRUSTED_CA_CERT_FILE;
    private static final String FTP_TEST_SSL_TRUSTED_CA_CERT_DATA;

    static {
        FTP_TEST_SSL_TRUSTED_CA_CERT_FILE = TestSSLPlugins.class.getClassLoader().getResource("ftp.crt").getPath();
        FTP_TEST_SSL_TRUSTED_CA_CERT_DATA = getFileContents(FTP_TEST_SSL_TRUSTED_CA_CERT_FILE);
    }

    @Test
    public void testNewTrustManager() throws Exception
    {
        StringReader r = new StringReader(FTP_TEST_SSL_TRUSTED_CA_CERT_DATA);
        List<X509Certificate> certs = TrustManagers.readPemEncodedX509Certificates(r);
        SSLPluginConfig config = new SSLPluginConfig(certs, false);
        config.newTrustManager(); // no error happens
    }

    @Test
    public void testNewSSLSocketFactory() throws Exception
    {
        StringReader r = new StringReader(FTP_TEST_SSL_TRUSTED_CA_CERT_DATA);
        List<X509Certificate> certs = TrustManagers.readPemEncodedX509Certificates(r);
        SSLPluginConfig config = new SSLPluginConfig(certs, false);

        SSLPlugins.newSSLSocketFactory(config, "example.com"); // no error happens
    }

    @Test
    public void testSslPluginConfigure()
    {
        // no error happens
        SSLPlugins.configure(
                Optional.of(false), false, Optional.of(FTP_TEST_SSL_TRUSTED_CA_CERT_FILE), Optional.empty());
    }

    @Test
    public void testSslPluginConfigureWithVerify()
    {
        // no error happens
        SSLPlugins.configure(
                Optional.of(true), false, Optional.of(FTP_TEST_SSL_TRUSTED_CA_CERT_FILE), Optional.empty());
    }

    @Test
    public void testReadTrustedCertificatesWithFile()
    {
        Optional<List<X509Certificate>> certs = SSLPlugins.readTrustedCertificatesForTesting(
                Optional.of(false), false, Optional.of(FTP_TEST_SSL_TRUSTED_CA_CERT_FILE), Optional.empty());
        assertThat(certs.get().size(), is(1));
        X509Certificate cert = certs.get().get(0);
        assertThat(cert.getSerialNumber().toString(), is("17761656583521120896"));
        assertThat(cert.getIssuerDN().toString(), is("CN=example.com, OU=Development devision, O=nobody.inc, L=Chiyoda-ku, ST=Tokyo, C=JP"));
    }

    @Test
    public void testReadTrustedCertificatesWithData()
    {
        Optional<List<X509Certificate>> certs = SSLPlugins.readTrustedCertificatesForTesting(
                Optional.of(false), false, Optional.empty(), Optional.of(FTP_TEST_SSL_TRUSTED_CA_CERT_DATA));
        assertThat(certs.get().size(), is(1));
        X509Certificate cert = certs.get().get(0);
        assertThat(cert.getSerialNumber().toString(), is("17761656583521120896"));
        assertThat(cert.getIssuerDN().toString(), is("CN=example.com, OU=Development devision, O=nobody.inc, L=Chiyoda-ku, ST=Tokyo, C=JP"));
    }

    private static String getFileContents(String path)
    {
        StringBuilder sb = new StringBuilder();
        try (InputStream is = new FileInputStream(new File(path))) {
            BufferedReader br = new BufferedReader(new InputStreamReader(is));
            String line = br.readLine();

            while (line != null) {
                sb.append(line).append("\n");
                line = br.readLine();
            }
        } catch (final IOException ex) {
            throw new UncheckedIOException(ex);
        }
        return sb.toString();
    }
}
