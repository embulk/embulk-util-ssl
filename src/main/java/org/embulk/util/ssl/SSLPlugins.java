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

import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

import java.io.ByteArrayInputStream;
import java.io.FileReader;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.io.UncheckedIOException;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * This class consists of {@code static} utility methods to generate {@link javax.net.ssl.SSLSocketFactory} eventually.
 */
public class SSLPlugins
{
    // SSLPlugins is only for SSL clients. SSL server implementation is out ouf scope.
    private SSLPlugins()
    {
    }

    private static enum VerifyMode
    {
        NO_VERIFY,
        CERTIFICATES,
        JVM_DEFAULT;
    }

    public static class SSLPluginConfig
    {
        static SSLPluginConfig NO_VERIFY = new SSLPluginConfig(VerifyMode.NO_VERIFY, false, EMPTY_CERTIFICATES);

        private final VerifyMode verifyMode;
        private final boolean verifyHostname;
        private final List<X509Certificate> certificates;

        private SSLPluginConfig(
            final VerifyMode verifyMode,
            final boolean verifyHostname,
            final List<byte[]> certificates)
        {
            this.verifyMode = verifyMode;
            this.verifyHostname = verifyHostname;
            this.certificates = Collections.unmodifiableList(certificates.stream().map(data -> {
                            try (ByteArrayInputStream in = new ByteArrayInputStream(data)) {
                                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                                return (X509Certificate) cf.generateCertificate(in);
                            } catch (IOException | CertificateException ex) {
                                throw new RuntimeException(ex);
                            }
                    }).collect(Collectors.toList()));
        }

        SSLPluginConfig(List<X509Certificate> certificates, boolean verifyHostname)
        {
            this.verifyMode = VerifyMode.CERTIFICATES;
            this.verifyHostname = verifyHostname;
            this.certificates = certificates;
        }

        static SSLPluginConfig useJvmDefault(boolean verifyHostname)
        {
            return new SSLPluginConfig(VerifyMode.JVM_DEFAULT, verifyHostname, EMPTY_CERTIFICATES);
        }

        private VerifyMode getVerifyMode()
        {
            return verifyMode;
        }

        private boolean getVerifyHostname()
        {
            return verifyHostname;
        }

        private List<byte[]> getCertData()
        {
            return Collections.unmodifiableList(this.certificates.stream().map(cert -> {
                    try {
                        return cert.getEncoded();
                    }
                    catch (CertificateEncodingException ex) {
                        throw new RuntimeException(ex);
                    }
                }).collect(Collectors.toList()));
        }

        public X509TrustManager[] newTrustManager()
        {
            try {
                switch (verifyMode) {
                case NO_VERIFY:
                    return new X509TrustManager[] { getNoVerifyTrustManager() };
                case CERTIFICATES:
                    return TrustManagers.newTrustManager(certificates);
                default: // JVM_DEFAULT
                    return TrustManagers.newDefaultJavaTrustManager();
                }
            }
            catch (IOException | GeneralSecurityException ex) {
                throw new RuntimeException(ex);
            }
        }
    }

    public static enum DefaultVerifyMode
    {
        VERIFY_BY_JVM_TRUSTED_CA_CERTS,
        NO_VERIFY;
    };

    /**
     */
    public static SSLPluginConfig configure(
            final Optional<Boolean> sslVerify,
            final boolean sslVerifyHostname,
            final Optional<String> sslTrustedCaCertFile,
            final Optional<String> sslTrustedCaCertData)
    {
        return configure(sslVerify,
                         sslVerifyHostname,
                         sslTrustedCaCertFile,
                         sslTrustedCaCertData,
                         DefaultVerifyMode.VERIFY_BY_JVM_TRUSTED_CA_CERTS);
    }

    /**
     */
    public static SSLPluginConfig configure(
            final Optional<Boolean> sslVerify,
            final boolean sslVerifyHostname,
            final Optional<String> sslTrustedCaCertFile,
            final Optional<String> sslTrustedCaCertData,
            final DefaultVerifyMode defaultVerifyMode)
    {
        if (sslVerify.orElse(defaultVerifyMode != DefaultVerifyMode.NO_VERIFY)) {
            final Optional<List<X509Certificate>> certs = readTrustedCertificates(
                    sslVerify, sslVerifyHostname, sslTrustedCaCertFile, sslTrustedCaCertData);
            if (certs.isPresent()) {
                return new SSLPluginConfig(certs.get(), sslVerifyHostname);
            }
            else {
                return SSLPluginConfig.useJvmDefault(sslVerifyHostname);
            }
        }
        else {
            return SSLPluginConfig.NO_VERIFY;
        }
    }

    private static Optional<List<X509Certificate>> readTrustedCertificates(
            final Optional<Boolean> sslVerify,
            final boolean sslVerifyHostname,
            final Optional<String> sslTrustedCaCertFile,
            final Optional<String> sslTrustedCaCertData)
    {
        String optionName;
        Reader reader;
        if (sslTrustedCaCertData.isPresent()) {
            optionName = "ssl_trusted_ca_cert_data";
            reader = new StringReader(sslTrustedCaCertData.get());
        }
        else if (sslTrustedCaCertFile.isPresent()) {
            optionName = "ssl_trusted_ca_cert_file '" + sslTrustedCaCertFile.get() + "'";
            try {
                reader = new FileReader(sslTrustedCaCertFile.get());
            }
            catch (IOException ex) {
                throw new UncheckedIOException("Failed to open " + optionName, ex);
            }
        }
        else {
            return Optional.empty();
        }

        List<X509Certificate> certs;
        try (Reader r = reader) {
            certs = TrustManagers.readPemEncodedX509Certificates(r);
            if (certs.isEmpty()) {
                throw new RuntimeException(optionName + " does not include valid X.509 PEM certificates");
            }
        } catch (final CertificateException ex) {
            throw new RuntimeException("Failed to read " + optionName, ex);
        } catch (final IOException ex) {
            throw new UncheckedIOException("Failed to read " + optionName, ex);
        }

        return Optional.of(certs);
    }

    static Optional<List<X509Certificate>> readTrustedCertificatesForTesting(
            final Optional<Boolean> sslVerify,
            final boolean sslVerifyHostname,
            final Optional<String> sslTrustedCaCertFile,
            final Optional<String> sslTrustedCaCertData)
    {
        return readTrustedCertificates(sslVerify, sslVerifyHostname, sslTrustedCaCertFile, sslTrustedCaCertData);
    }

    /**
     */
    public static SSLSocketFactory newSSLSocketFactory(SSLPluginConfig config, String hostname)
    {
        try {
            return TrustManagers.newSSLSocketFactory(
                    null,  // TODO sending client certificate is not implemented yet
                    config.newTrustManager(),
                    config.getVerifyHostname() ? hostname : null);
        }
        catch (KeyManagementException ex) {
            throw new RuntimeException(ex);
        }
    }

    private static class NoVerifyTrustManager
            implements X509TrustManager
    {
        static final NoVerifyTrustManager INSTANCE = new NoVerifyTrustManager();

        private NoVerifyTrustManager()
        { }

        @Override
        public X509Certificate[] getAcceptedIssuers()
        {
            return null;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] certs, String authType)
        { }

        @Override
        public void checkServerTrusted(X509Certificate[] certs, String authType)
        { }
    }

    private static X509TrustManager getNoVerifyTrustManager()
    {
        return NoVerifyTrustManager.INSTANCE;
    }

    private static final List<byte[]> EMPTY_CERTIFICATES = Collections.unmodifiableList(new ArrayList<byte[]>());
}
