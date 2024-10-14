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

import kotlinx.serialization.json.JsonObject

/* ============= ------------------ ============= */

/**
 * A wrapper for a Json Web Key given by some implementation.
 */
@Suppress("EXPECT_ACTUAL_CLASSIFIERS_ARE_IN_BETA_WARNING")
expect sealed interface JWK {
    /**
     * All the parameters used for creating the key.
     */
    val parameters: JsonObject

    /**
     * Only public parameters of this key.
     */
    val publicParameters: JsonObject

    /**
     * Optimized shortcut for:
     *
     * ```
     * parameters["kty"]!.asString
     * ```
     */
    val kty: String

    /**
     * Optimized shortcut for:
     *
     * ```
     * parameters["use"]?.asStringOrNull
     * ```
     */
    val use: String?

    /**
     * Optimized shortcut for:
     *
     * ```
     * parameters["kid"]?.asStringOrNull
     * ```
     */
    val kid: String?

    /**
     * Optimized shortcut for:
     *
     * ```
     * parameters["alg"]?.asStringOrNull
     * ```
     */
    val alg: String?

    /**
     * Optimized shortcut for:
     *
     * ```
     * parameters["alg"]?.asJsonArray?.map { it.asString }
     * ```
     */
    val keyOps: List<String>?
}

/* ============= ------------------ ============= */

/**
 * Construct a new [JWK] using the given [parameters].
 */
expect fun createJWKCatching(parameters: JsonObject): Result<JWK>

/**
 * Construct a new [JWK] using the given [parameters].
 *
 * If construction fails, throw an [IllegalArgumentException].
 */
fun createJWK(parameters: JsonObject): JWK {
    return createJWKCatching(parameters).getOrThrow()
}

/**
 * Construct a new [JWK] using the given [parameters].
 *
 * If construction fails, return `null`.
 */
fun createJWKOrNull(parameters: JsonObject): JWK? {
    return createJWKCatching(parameters).getOrNull()
}

/* ============= ------------------ ============= */

/**
 * Decode this string into a [JWK].
 */
expect fun String.decodeJWKCatching(): Result<JWK>

/**
 * Decode this string into a [JWK].
 *
 * If decoding fails, throw an [IllegalArgumentException].
 */
fun String.decodeJWK(): JWK {
    return decodeJWKCatching().getOrThrow()
}

/**
 * Decode this string into a [JWK].
 *
 * If decoding fails, return `null`.
 */
fun String.decodeJWKOrNull(): JWK? {
    return decodeJWKCatching().getOrNull()
}

/* ============= ------------------ ============= */
