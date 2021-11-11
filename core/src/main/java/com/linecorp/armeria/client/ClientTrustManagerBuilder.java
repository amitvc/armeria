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

import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.X509ExtendedTrustManager;

import com.linecorp.armeria.server.RoutingTrieBuilder;

class ClientTrustManagerBuilder {
    private final Map<String, ClientTrustManagerAction> actions;

    public ClientTrustManagerBuilder() {
        actions = new HashMap<>();
    }

    ClientTrustManagerBuilder noVerify(String hostnamePattern) {
        actions.put(hostnamePattern, ClientTrustManagerAction.noVerify());
        return this;
    }

    ClientTrustManagerBuilder reject(String hostnamePattern) {
        actions.put(hostnamePattern, ClientTrustManagerAction.noVerify());
        return this;
    }

    ClientTrustManagerBuilder verifySignaturesOnly(String hostnamePattern) {
        actions.put(hostnamePattern, ClientTrustManagerAction.verifySignaturesOnly());
        return this;
    }

    ClientTrustManagerBuilder verifyAll(String hostnamePattern) {
        actions.put(hostnamePattern, ClientTrustManagerAction.verifyAll());
        return this;
    }

    ClientTrustManagerBuilder verifyFingerprintOnly(String hostnamePattern, String algorithm, String... fingerprints) {
        actions.put(hostnamePattern, ClientTrustManagerAction.verifyFingerprintsOnly(algorithm, fingerprints));
        return this;
    }

    private void action(String hostnamePattern,ClientTrustManagerAction action ) {
        actions.put(hostnamePattern, action);
    }

    X509ExtendedTrustManager build() {
        final RoutingTrieBuilder<ClientTrustManagerAction> builder = new RoutingTrieBuilder<>();

        actions.entrySet().stream().forEach(e-> .);
        return new DefaultClientTrustManager();
    }
}
