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

import org.cufy.jose.internal.asJsonObjectOrNull
import org.cufy.jose.internal.decodeJsonOrNull
import kotlin.Result.Companion.failure
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/* ============= ------------------ ============= */

/**
 * The components of either a JWE Compact Serialization or a JWS Compact Serialization.
 *
 * [RFC7515-7.1](https://datatracker.ietf.org/doc/html/rfc7515#section-7.1)
 * [RFC7516-7.1](https://www.rfc-editor.org/rfc/rfc7516#section-7.1)
 */
sealed class CompactJWT {
    /**
     * `BASE64URL(UTF8(JWE Protected Header))`
     */
    abstract val header: String

    /**
     * The components seperated with periods ('.').
     */
    abstract val value: String

    /**
     * The decoded header of the jwt.
     */
    @OptIn(ExperimentalEncodingApi::class)
    val decodedHeaderOrNull by lazy {
        Base64.UrlSafe.decode(header)
            .decodeToString()
            .decodeJsonOrNull()
            ?.asJsonObjectOrNull
    }
}

/* ============= ------------------ ============= */

/**
 * Split this string into either CompactJWE or CompactJWS
 * depending on the number of periods ('.') in this string.
 */
fun String.decodeCompactJWTCatching(): Result<CompactJWT> {
    return when (count { it == '.' }) {
        2 -> decodeCompactJWSCatching()
        4 -> decodeCompactJWECatching()
        else -> failure(IllegalArgumentException("Malformed JWT was presented"))
    }
}

/**
 * Split this string into either CompactJWE or CompactJWS
 * depending on the number of periods ('.') in this string.
 *
 * If decode fails, throw an [IllegalArgumentException].
 */
fun String.decodeCompactJWT(): CompactJWT {
    return when (count { it == '.' }) {
        2 -> decodeCompactJWS()
        4 -> decodeCompactJWE()
        else -> throw IllegalArgumentException("Malformed JWT was presented")
    }
}

/**
 * Split this string into either CompactJWE or CompactJWS
 * depending on the number of periods ('.') in this string.
 *
 * If decode fails, return `null`.
 */
fun String.decodeCompactJWTOrNull(): CompactJWT? {
    return when (count { it == '.' }) {
        2 -> decodeCompactJWSOrNull()
        4 -> decodeCompactJWEOrNull()
        else -> null
    }
}

/**
 * Using the number of periods ('.') in this string,
 * determine if this string is JWT.
 */
fun String.isCompactJWTQuick(): Boolean {
    return when (count { it == '.' }) {
        2, 4 -> true
        else -> false
    }
}

/* ============= ------------------ ============= */
