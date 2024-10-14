/*
 *	Copyright 2024 cufy.org and meemer.com
 *
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *
 *	    http://www.apache.org/licenses/LICENSE-2.0
 *
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 */
package org.cufy.jose

/**
 * Return the default signing alg for a key with the given parameters.
 */
internal fun defaultSigAlg(kty: String, use: String?, alg: String?): String? {
    if (use != null && use != "sig")
        return null

    if (alg != null)
        return alg

    return when (kty) {
        "RSA" -> "RS384"
        "EC" -> "ES384"
        else -> null
    }
}

/**
 * Return the default encryption alg for a key with the given parameters.
 */
internal fun defaultEncAlg(kty: String, use: String?, alg: String?): String? {
    if (use != null && use != "enc")
        return null

    if (alg != null)
        return alg

    return when (kty) {
        "RSA" -> "RSA-OAEP-256"
        "EC" -> "ECDH-ES+A256KW"
        else -> null
    }
}

/**
 * Return the default encryption enc for a key with the given parameters.
 */
internal fun defaultEncEnc(kty: String, use: String?, alg: String?): String? {
    return "A128CBC-HS256"
}

/**
 * Return true if the given key type [kty] is compatible with [alg].
 */
internal fun isCompatKtyAlg(kty: String, alg: String): Boolean {
    when (kty) {
        "RSA" -> when (alg) {
            "RS256",
            "RS384",
            "RS512",

            "PS256",
            "PS384",
            "PS512",

            "RSA1_5",
            "RSA-OAEP",
            "RSA-OAEP-256",

            -> return true
        }

        "EC" -> when (alg) {
            "ES256",
            "ES384",
            "ES512",
            "ES256K",
            "EdDSA",

            "ECDH-ES",
            "ECDH-ES+A128KW",
            "ECDH-ES+A192KW",
            "ECDH-ES+A256KW",

            -> return true
        }
    }

    return false
}
