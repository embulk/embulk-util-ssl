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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.Reader;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMParser;
import sun.security.ssl.SSLSocketImpl;

public class TrustManagers {
    private TrustManagers() {
        // No instantiation.
    }

    public static KeyStore readDefaultJavaKeyStore() throws IOException, KeyStoreException, CertificateException {
        String path = (System.getProperty("java.home") + "/lib/security/cacerts").replace('/', File.separatorChar);
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            try (FileInputStream in = new FileInputStream(path)) {
                keyStore.load(in, null);  // password=null because cacerts file is not encrypted
            }
            return keyStore;
        } catch (final NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);  // TODO assertion exception?
        }
    }

    public static List<X509Certificate> readDefaultJavaTrustedCertificates()
            throws IOException, CertificateException, KeyStoreException, InvalidAlgorithmParameterException {
        KeyStore keyStore = readDefaultJavaKeyStore();
        PKIXParameters params = new PKIXParameters(keyStore);
        List<X509Certificate> certs = new ArrayList<>();
        for (TrustAnchor trustAnchor : params.getTrustAnchors()) {
            certs.add(trustAnchor.getTrustedCert());
        }
        return certs;
    }

    public static List<X509Certificate> readPemEncodedX509Certificates(final Reader reader) throws IOException, CertificateException {
        // this method abuses CertificateParsingException because its javadoc says
        // CertificateParsingException is only for DER-encoded formats.

        JcaX509CertificateConverter conv = new JcaX509CertificateConverter();
        List<X509Certificate> certs = new ArrayList<>();

        try {
            PEMParser pemParser = new PEMParser(reader);
            // PEMParser#close is unnecessary because it just closes underlying reader

            while (true) {
                Object pem = pemParser.readObject();

                if (pem == null) {
                    break;
                }

                if (pem instanceof X509CertificateHolder) {
                    X509Certificate cert = conv.getCertificate((X509CertificateHolder) pem);
                    certs.add(cert);
                }
            }
        } catch (final PEMException ex) {
            // throw when parsing PemObject to Object fails
            throw new CertificateParsingException(ex);
        } catch (final IOException ex) {
            if (ex.getClass().equals(IOException.class)) {
                String message = ex.getMessage();
                if (message.startsWith("unrecognised object: ")) {
                    // thrown at org.bouncycastle.openssl.PemParser.readObject when key type (header of a pem) is
                    // unknown.
                    throw new CertificateParsingException(ex);
                } else if (message.startsWith("-----END ") && message.endsWith(" not found")) {
                    // thrown at org.bouncycastle.util.io.pem.PemReader.loadObject when a pem file format is invalid
                    throw new CertificateParsingException(ex);
                }
            } else {
                throw ex;
            }
        }

        return certs;
    }

    public static KeyStore buildKeyStoreFromTrustedCertificates(final List<X509Certificate> certificates) throws KeyStoreException {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try {
            keyStore.load(null);
        } catch (final IOException | CertificateException | NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
        int i = 0;
        for (X509Certificate cert : certificates) {
            keyStore.setCertificateEntry("cert_" + i, cert);
            i++;
        }
        return keyStore;
    }

    public static X509TrustManager[] newTrustManager(final List<X509Certificate> trustedCertificates) throws KeyStoreException {
        try {
            TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            KeyStore keyStore = buildKeyStoreFromTrustedCertificates(trustedCertificates);
            factory.init(keyStore);
            List<X509TrustManager> tms = new ArrayList<>();
            for (TrustManager tm : factory.getTrustManagers()) {
                if (tm instanceof X509TrustManager) {
                    tms.add((X509TrustManager) tm);
                }
            }
            return tms.toArray(new X509TrustManager[tms.size()]);
        } catch (final NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);  // TODO assertion exception?
        }
    }

    public static X509TrustManager[] newDefaultJavaTrustManager()
            throws IOException, CertificateException, KeyStoreException, InvalidAlgorithmParameterException {
        return newTrustManager(readDefaultJavaTrustedCertificates());
    }

    @SuppressWarnings("checkstyle:AbbreviationAsWordInName")
    public static SSLContext newSSLContext(KeyManager[] keyManager, X509TrustManager[] trustManager)
            throws KeyManagementException {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(
                    keyManager,
                    trustManager,
                    new SecureRandom());
            return context;
        } catch (final NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
    }

    @SuppressWarnings("checkstyle:AbbreviationAsWordInName")
    public static SSLSocketFactory newSSLSocketFactory(
            final KeyManager[] keyManager, final X509TrustManager[] trustManager, final String verifyHostname)
            throws KeyManagementException {
        SSLContext context = newSSLContext(keyManager, trustManager);
        SSLSocketFactory factory = context.getSocketFactory();
        if (verifyHostname == null) {
            return factory;
        } else {
            return new VerifyHostNameSSLSocketFactory(factory, verifyHostname);
        }
    }

    @SuppressWarnings("checkstyle:AbbreviationAsWordInName")
    private static class VerifyHostNameSSLSocketFactory extends SSLSocketFactory {
        private final SSLSocketFactory next;
        private final String hostname;

        public VerifyHostNameSSLSocketFactory(final SSLSocketFactory next, final String hostname) {
            this.next = next;
            this.hostname = hostname;
        }

        @Override
        public String[] getDefaultCipherSuites() {
            return next.getDefaultCipherSuites();
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return next.getSupportedCipherSuites();
        }

        @Override
        public Socket createSocket(final Socket s, final String host, final int port, final boolean autoClose) throws IOException {
            Socket sock = next.createSocket(s, host, port, autoClose);
            setSSLParameters(sock, false);
            return sock;
        }

        @Override
        public Socket createSocket(final String host, final int port) throws IOException, UnknownHostException {
            Socket sock = next.createSocket(host, port);
            setSSLParameters(sock, false);
            return sock;
        }

        @Override
        public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
                throws IOException, UnknownHostException {
            Socket sock = next.createSocket(host, port, localHost, localPort);
            setSSLParameters(sock, false);
            return sock;
        }

        @Override
        public Socket createSocket(final InetAddress host, final int port) throws IOException {
            Socket sock = next.createSocket(host, port);
            setSSLParameters(sock, true);
            return sock;
        }

        @Override
        public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
                throws IOException {
            Socket sock = next.createSocket(address, port, localAddress, localPort);
            setSSLParameters(sock, true);
            return sock;
        }

        private void setSSLParameters(final Socket sock, final boolean setHostname) {
            if (sock instanceof SSLSocket) {
                SSLSocket s = (SSLSocket) sock;
                String identAlgorithm = s.getSSLParameters().getEndpointIdentificationAlgorithm();
                if (identAlgorithm != null && identAlgorithm.equalsIgnoreCase("HTTPS")) {
                    // hostname verification is already configured.
                } else {
                    if (setHostname && s instanceof SSLSocketImpl) {
                        ((SSLSocketImpl) s).setHost(hostname);
                    }
                    SSLParameters params = s.getSSLParameters();
                    params.setEndpointIdentificationAlgorithm("HTTPS");
                    s.setSSLParameters(params);
                    // s.startHandshake
                }
            }
        }
    }
}
