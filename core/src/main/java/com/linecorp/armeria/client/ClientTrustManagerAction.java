/*
 * Copyright 2021 LINE Corporation
 *
 * LINE Corporation licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package com.linecorp.armeria.client;

import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

import java.security.cert.CertificateException;

import io.netty.handler.ssl.util.FingerprintTrustManagerFactory;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;

@FunctionalInterface
public interface ClientTrustManagerAction {

    static ClientTrustManagerAction noVerify() {
        return new ClientTrustManagerAction() {
            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
                // Accept any certificate
            }
        };
    }


    static ClientTrustManagerAction reject() {
        return new ClientTrustManagerAction() {
            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
                throw new CertificateNotYetValidException(); // We reject any certificate
            }
        };
    }

    static ClientTrustManagerAction verifySignaturesOnly() {
        return new ClientTrustManagerAction() {
            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
                //chain[0].verify();
            }
        };
    }

    static ClientTrustManagerAction verifyFingerprintsOnly(String algo, String... fingerprint) {
        return new ClientTrustManagerAction() {
            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
                FingerprintTrustManagerFactory factory = FingerprintTrustManagerFactory
                        .builder(algo)
                        .fingerprints(fingerprint).build();

                for (TrustManager tm : factory.getTrustManagers()) {
                    if (tm instanceof X509TrustManager) {
                        ((X509TrustManager) tm).checkServerTrusted(chain, authType);
                    }
                }
            }
        };
    }

    static ClientTrustManagerAction verifyAll() {
        return new ClientTrustManagerAction() {
            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {

            }
        };
    }

    void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException, java.security.cert.CertificateException;
}