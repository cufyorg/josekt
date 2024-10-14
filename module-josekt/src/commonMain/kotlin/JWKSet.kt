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

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlin.Result.Companion.failure
import kotlin.Result.Companion.success

/* ============= ------------------ ============= */

typealias JWKSet = Set<JWK>

/* ============= ------------------ ============= */

/**
 * Construct a new [JWKSet] using the given [parameters].
 */
fun createJWKSetCatching(parameters: JsonObject): Result<JWKSet> {
    val keys = parameters["keys"]

    if (keys !is JsonArray)
        return failure(IllegalArgumentException("Bad JWKSet keys. Expected JsonArray"))

    val count = keys.size
    return success(buildSet(count) {
        for (i in 0..<count) {
            val key = keys[i]

            if (key !is JsonObject)
                return failure(IllegalArgumentException("Bad JWK. Expected JsonObject"))

            this += createJWKCatching(key).getOrElse { return failure(it) }
        }
    })
}

/**
 * Construct a new [JWKSet] using the given [parameters].
 *
 * If construction fails, throw an [IllegalArgumentException].
 */
fun createJWKSet(parameters: JsonObject): JWKSet {
    return createJWKSetCatching(parameters).getOrThrow()
}

/**
 * Construct a new [JWKSet] using the given [parameters].
 *
 * If construction fails, return `null`.
 */
fun createJWKSetOrNull(parameters: JsonObject): JWKSet? {
    return createJWKSetCatching(parameters).getOrNull()
}

/* ============= ------------------ ============= */

/**
 * Decode this string into a [JWKSet].
 */
expect fun String.decodeJWKSetCatching(): Result<JWKSet>

/**
 * Decode this string into a [JWKSet].
 *
 * If decoding fails, throw an [IllegalArgumentException].
 */
fun String.decodeJWKSet(): JWKSet {
    return decodeJWKSetCatching().getOrThrow()
}

/**
 * Decode this string into a [JWKSet].
 *
 * If construction fails, return `null`.
 */
fun String.decodeJWKSetOrNull(): JWKSet? {
    return decodeJWKSetCatching().getOrNull()
}

/* ============= ------------------ ============= */

fun JWKSet.findEncrypt(kid: String? = null, alg: String? = null) =
    filterSortedEncrypt(kid, alg).firstOrNull()

fun JWKSet.findDecrypt(kid: String? = null, alg: String? = null) =
    filterSortedDecrypt(kid, alg).firstOrNull()

fun JWKSet.findSign(kid: String? = null, alg: String? = null) =
    filterSortedSign(kid, alg).firstOrNull()

fun JWKSet.findVerify(kid: String? = null, alg: String? = null) =
    filterSortedVerify(kid, alg).firstOrNull()

/* ============= ------------------ ============= */

fun JWKSet.filterSortedEncrypt(kid: String? = null, alg: String? = null) =
    filterSorted("enc", "encrypt", kid, alg)

fun JWKSet.filterSortedDecrypt(kid: String? = null, alg: String? = null) =
    filterSorted("enc", "decrypt", kid, alg)

fun JWKSet.filterSortedSign(kid: String? = null, alg: String? = null) =
    filterSorted("sig", "sign", kid, alg)

fun JWKSet.filterSortedVerify(kid: String? = null, alg: String? = null) =
    filterSorted("sig", "verify", kid, alg)

/* ============= ------------------ ============= */

private fun JWKSet.filterSorted(use: String, op: String, kid: String?, alg: String?): List<JWK> {
    val filtered = toMutableList()

    if (kid != null) {
        filtered.removeAll {
            it.kid != kid
        }
    }

    filtered.removeAll {
        it.use != null && it.use != use
    }
    filtered.removeAll {
        it.keyOps?.contains(op) ?: false
    }

    if (alg != null) {
        filtered.removeAll {
            it.alg != null && it.alg != alg
        }
        filtered.removeAll {
            !isCompatKtyAlg(it.kty, alg)
        }
    }

    filtered.sortBy {
        var score = 0

        if (it.kid != null) score -= 100
        if (it.use != null) score -= 1
        if (it.keyOps != null) score -= 1
        if (it.alg != null) score -= 1

        score
    }

    return filtered
}

/* ============= ------------------ ============= */
