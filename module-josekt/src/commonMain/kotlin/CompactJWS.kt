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
import kotlin.Result.Companion.success
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/* ============= ------------------ ============= */

/**
 * The components of a JWS Compact Serialization.
 *
 * [RFC7515-7.1](https://datatracker.ietf.org/doc/html/rfc7515#section-7.1)
 */
data class CompactJWS(
    /**
     * `BASE64URL(UTF8(JWS Protected Header))`
     */
    override val header: String,
    /**
     * `BASE64URL(JWS Payload)`
     */
    val payload: String,
    /**
     * `BASE64URL(JWS Signature)`
     */
    val signature: String,
) : CompactJWT() {
    /**
     * The components seperated with periods ('.').
     *
     * ```
     * BASE64URL(UTF8(JWS Protected Header)) || '.' ||
     * BASE64URL(JWS Payload) || '.' ||
     * BASE64URL(JWS Signature)
     * ```
     */
    override val value by lazy {
        buildString {
            append(header)
            append('.')
            append(payload)
            append('.')
            append(signature)
        }
    }

    /**
     * The decoded payload of the jwt.
     */
    @OptIn(ExperimentalEncodingApi::class)
    val decodedPayloadOrNull by lazy {
        Base64.UrlSafe.decode(payload)
            .decodeToString()
            .decodeJsonOrNull()
            ?.asJsonObjectOrNull
    }
}

/* ============= ------------------ ============= */

/**
 * Split this string into JWS Compact Serialization Components.
 */
fun String.decodeCompactJWSCatching(): Result<CompactJWS> {
    return decodeCompactJWSOrNull()
        ?.let { success(it) }
        ?: failure(IllegalArgumentException("Malformed JWS was presented"))
}

/**
 * Split this string into JWS Compact Serialization Components.
 *
 * If decode fails, throw an [IllegalArgumentException].
 */
fun String.decodeCompactJWS(): CompactJWS {
    return decodeCompactJWSCatching().getOrThrow()
}

/**
 * Split this string into JWS Compact Serialization Components.
 *
 * If decode fails, return `null`.
 */
fun String.decodeCompactJWSOrNull(): CompactJWS? {
    val segments = splitToSequence('.').iterator()
    return CompactJWS(
        header = if (segments.hasNext()) segments.next() else return null,
        payload = if (segments.hasNext()) segments.next() else return null,
        signature = if (segments.hasNext()) segments.next() else return null,
    )
}

/**
 * Using the number of periods ('.') in this string,
 * determine if this string is JWS Compact Serialization.
 */
fun String.isCompactJWSQuick(): Boolean {
    return 2 == count { it == '.' }
}

/* ============= ------------------ ============= */

/**
 * Find suitable key in [jwks], sign JWT components
 * and return JWS components.
 *
 * @param defaultConstraints enables protection over well-known dangerous scenarios.
 */
expect fun JWT.signCatching(jwks: JWKSet, defaultConstraints: Boolean = true): Result<CompactJWS>

/**
 * Find suitable key in [jwks], sign JWT components
 * and return JWS components.
 *
 * If signing fails, throw an [IllegalArgumentException].
 *
 * @param defaultConstraints enables protection over well-known dangerous scenarios.
 */
fun JWT.sign(jwks: JWKSet, defaultConstraints: Boolean = true): CompactJWS {
    return signCatching(jwks, defaultConstraints).getOrThrow()
}

/**
 * Find suitable key in [jwks], sign JWT components
 * and return JWS components.
 *
 * If signing fails, return `null`.
 *
 * @param defaultConstraints enables protection over well-known dangerous scenarios.
 */
fun JWT.signOrNull(jwks: JWKSet, defaultConstraints: Boolean = true): CompactJWS? {
    return signCatching(jwks, defaultConstraints).getOrNull()
}

/* ============= ------------------ ============= */

/**
 * Find suitable key in [jwks], sign JWT components
 * and return JWS components.
 *
 * @param defaultConstraints enables protection over well-known dangerous scenarios.
 */
fun JWT.signToStringCatching(jwks: JWKSet, defaultConstraints: Boolean = true): Result<String> {
    return signCatching(jwks, defaultConstraints).map { it.value }
}

/**
 * Find suitable key in [jwks], sign JWT components
 * and return JWS components.
 *
 * If signing fails, throw an [IllegalArgumentException].
 *
 * @param defaultConstraints enables protection over well-known dangerous scenarios.
 */
fun JWT.signToString(jwks: JWKSet, defaultConstraints: Boolean = true): String {
    return sign(jwks, defaultConstraints).value
}

/**
 * Find suitable key in [jwks], sign JWT components
 * and return JWS components.
 *
 * If signing fails, return `null`.
 *
 * @param defaultConstraints enables protection over well-known dangerous scenarios.
 */
fun JWT.signToStringOrNull(jwks: JWKSet, defaultConstraints: Boolean = true): String? {
    return signOrNull(jwks, defaultConstraints)?.value
}

/* ============= ------------------ ============= */

/**
 * Decode JWS components, find matching key in [jwks],
 * verify signature and return true if verified.
 *
 * > If the algorithm is set to `none`, no verification will be done.
 *
 * @param defaultConstraints enables protection over well-known dangerous scenarios.
 */
expect fun CompactJWS.verifyCatching(jwks: JWKSet, defaultConstraints: Boolean = true): Result<Boolean>

/**
 * Decode JWS components, find matching key in [jwks],
 * verify signature and return true if verified.
 *
 * If verification fails, throw an [IllegalArgumentException].
 *
 * > If the algorithm is set to `none`, no verification will be done.
 *
 * @param defaultConstraints enables protection over well-known dangerous scenarios.
 */
fun CompactJWS.verify(jwks: JWKSet, defaultConstraints: Boolean = true): Boolean {
    return verifyCatching(jwks, defaultConstraints).getOrThrow()
}

/**
 * Decode JWS components, find matching key in [jwks],
 * verify signature and return true if verified.
 *
 * If verification fails, return `null`.
 *
 * > If the algorithm is set to `none`, no verification will be done.
 *
 * @param defaultConstraints enables protection over well-known dangerous scenarios.
 */
fun CompactJWS.verifyOrNull(jwks: JWKSet, defaultConstraints: Boolean = true): Boolean? {
    return verifyCatching(jwks, defaultConstraints).getOrNull()
}

/* ============= ------------------ ============= */

/**
 * Decode JWS components, find matching key in [jwks],
 * verify signature and return true if verified.
 *
 * > If the algorithm is set to `none`, no verification will be done.
 *
 * @param defaultConstraints enables protection over well-known dangerous scenarios.
 */
fun String.verifyCompactJWSCatching(jwks: JWKSet, defaultConstraints: Boolean = true): Result<Boolean> {
    return decodeCompactJWSCatching().fold(
        { it.verifyCatching(jwks, defaultConstraints) },
        { failure(it) }
    )
}

/**
 * Decode JWS components, find matching key in [jwks],
 * verify signature and return true if verified.
 *
 * If verification fails, throw an [IllegalArgumentException].
 *
 * > If the algorithm is set to `none`, no verification will be done.
 *
 * @param defaultConstraints enables protection over well-known dangerous scenarios.
 */
fun String.verifyCompactJWS(jwks: JWKSet, defaultConstraints: Boolean = true): Boolean {
    return decodeCompactJWS().verify(jwks, defaultConstraints)
}

/**
 * Decode JWS components, find matching key in [jwks],
 * verify signature and return true if verified.
 *
 * If verification fails, return `null`.
 *
 * > If the algorithm is set to `none`, no verification will be done.
 *
 * @param defaultConstraints enables protection over well-known dangerous scenarios.
 */
fun String.verifyCompactJWSOrNull(jwks: JWKSet, defaultConstraints: Boolean = true): Boolean? {
    return decodeCompactJWSOrNull()?.verifyOrNull(jwks, defaultConstraints)
}

/* ============= ------------------ ============= */

/**
 * Decode JWS components, find matching key in [jwks],
 * verify signature and return JWT components.
 *
 * > If the algorithm is set to `none`, no verification will be done.
 *
 * @param defaultConstraints enables protection over well-known dangerous scenarios.
 */
expect fun CompactJWS.verifiedCatching(jwks: JWKSet, defaultConstraints: Boolean = true): Result<JWT>

/**
 * Decode JWS components, find matching key in [jwks],
 * verify signature and return JWT components.
 *
 * If verification fails, throw an [IllegalArgumentException].
 *
 * > If the algorithm is set to `none`, no verification will be done.
 *
 * @param defaultConstraints enables protection over well-known dangerous scenarios.
 */
fun CompactJWS.verified(jwks: JWKSet, defaultConstraints: Boolean = true): JWT {
    return verifiedCatching(jwks, defaultConstraints).getOrThrow()
}

/**
 * Decode JWS components, find matching key in [jwks],
 * verify signature and return JWT components.
 *
 * If verification fails, return `null`.
 *
 * > If the algorithm is set to `none`, no verification will be done.
 *
 * @param defaultConstraints enables protection over well-known dangerous scenarios.
 */
fun CompactJWS.verifiedOrNull(jwks: JWKSet, defaultConstraints: Boolean = true): JWT? {
    return verifiedCatching(jwks, defaultConstraints).getOrNull()
}

/* ============= ------------------ ============= */

/**
 * Decode JWS components, find matching key in [jwks],
 * verify signature and return JWT components.
 *
 * > If the algorithm is set to `none`, no verification will be done.
 *
 * @param defaultConstraints enables protection over well-known dangerous scenarios.
 */
fun String.verifiedCompactJWSCatching(jwks: JWKSet, defaultConstraints: Boolean = true): Result<JWT> {
    return decodeCompactJWSCatching().fold(
        { it.verifiedCatching(jwks, defaultConstraints) },
        { failure(it) }
    )
}

/**
 * Decode JWS components, find matching key in [jwks],
 * verify signature and return JWT components.
 *
 * If verification fails, throw an [IllegalArgumentException].
 *
 * > If the algorithm is set to `none`, no verification will be done.
 *
 * @param defaultConstraints enables protection over well-known dangerous scenarios.
 */
fun String.verifiedCompactJWS(jwks: JWKSet, defaultConstraints: Boolean = true): JWT {
    return decodeCompactJWS().verified(jwks, defaultConstraints)
}

/**
 * Decode JWS components, find matching key in [jwks],
 * verify signature and return JWT components.
 *
 * If verification fails, return `null`.
 *
 * > If the algorithm is set to `none`, no verification will be done.
 *
 * @param defaultConstraints enables protection over well-known dangerous scenarios.
 */
fun String.verifiedCompactJWSOrNull(jwks: JWKSet, defaultConstraints: Boolean = true): JWT? {
    return decodeCompactJWSOrNull()?.verifiedOrNull(jwks, defaultConstraints)
}

/* ============= ------------------ ============= */

/**
 * Decode JWS components, without signature verification.
 */
expect fun CompactJWS.unverifiedCatching(): Result<JWT>

/**
 * Decode JWS components, without signature verification.
 *
 * If decoding fails, throw an [IllegalArgumentException].
 */
fun CompactJWS.unverified(): JWT {
    return unverifiedCatching().getOrThrow()
}

/**
 * Decode JWS components, without signature verification.
 *
 * If decoding fails, return `null`.
 */
fun CompactJWS.unverifiedOrNull(): JWT? {
    return unverifiedCatching().getOrNull()
}

/* ============= ------------------ ============= */

/**
 * Decode JWS components, without signature verification.
 *
 * If decoding fails, throw an [IllegalArgumentException].
 */
fun String.unverifiedCompactJWSCatching(): Result<JWT> {
    return decodeCompactJWSCatching().fold(
        { it.unverifiedCatching() },
        { failure(it) }
    )
}

/**
 * Decode JWS components, without signature verification.
 *
 * If decoding fails, throw an [IllegalArgumentException].
 */
fun String.unverifiedCompactJWS(): JWT {
    return decodeCompactJWS().unverified()
}

/**
 * Decode JWS components, without signature verification.
 *
 * If decoding fails, return `null`.
 */
fun String.unverifiedCompactJWSOrNull(): JWT? {
    return decodeCompactJWSOrNull()?.unverifiedOrNull()
}

/* ============= ------------------ ============= */
