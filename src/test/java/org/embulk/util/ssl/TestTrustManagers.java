/*
 * Copyright 2018 The Embulk project
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

import com.google.common.io.Resources;
import java.io.StringReader;
import java.security.cert.X509Certificate;
import java.util.List;
import org.junit.Before;
import org.junit.Test;

public class TestTrustManagers {
    private static String FTP_TEST_SSL_TRUSTED_CA_CERT_DATA;

    @Before
    public void createResources() {
        FTP_TEST_SSL_TRUSTED_CA_CERT_DATA = Resources.getResource("ftp.crt").getPath();
    }

    @Test
    public void testNewTrustManager() throws Exception {
        StringReader r = new StringReader(FTP_TEST_SSL_TRUSTED_CA_CERT_DATA);
        List<X509Certificate> certs = TrustManagers.readPemEncodedX509Certificates(r);
        TrustManagers.newTrustManager(certs); // no error happens
    }

    @Test
    public void testNewDefaultJavaTrustManager() throws Exception {
        TrustManagers.newDefaultJavaTrustManager(); // no error happens
    }

    @SuppressWarnings("checkstyle:AbbreviationAsWordInName")
    @Test
    public void testNewSSLSocketFactory() throws Exception {
        TrustManagers.newSSLSocketFactory(null, null, "example.com"); // no error happens
    }
}
