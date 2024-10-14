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
import org.jose4j.jwk.JsonWebKey
import org.jose4j.jwk.JsonWebKeySet
import kotlin.Result.Companion.failure
import kotlin.Result.Companion.success

/* ============= ------------------ ============= */

@Suppress("EXPECT_ACTUAL_CLASSIFIERS_ARE_IN_BETA_WARNING")
actual sealed interface JWK {
    actual val parameters: JsonObject
    actual val publicParameters: JsonObject

    actual val kty: String
    actual val use: String?
    actual val kid: String?
    actual val alg: String?
    actual val keyOps: List<String>?
}

/* ============= ------------------ ============= */

fun JsonWebKey.toJWKCatching(): Result<JWK> {
    val level = JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE
    val parameters = toParams(level).jose4j_toJsonElementCatching().getOrElse { return failure(it) }
    return success(Jose4jJWK(this, parameters))
}

fun JsonWebKey.toJWK(): JWK {
    return toJWKCatching().getOrThrow()
}

fun JsonWebKey.toJWKOrNull(): JWK? {
    return toJWKCatching().getOrNull()
}

/* ============= ------------------ ============= */

fun JsonWebKeySet.toJWKSetCatching(): Result<JWKSet> {
    return success(jsonWebKeys.mapTo(mutableSetOf()) {
        it.toJWKCatching().getOrElse { return failure(it) }
    })
}

fun JsonWebKeySet.toJWKSet(): JWKSet {
    return toJWKSetCatching().getOrThrow()
}

fun JsonWebKeySet.toJWKSetOrNull(): JWKSet? {
    return toJWKSetCatching().getOrNull()
}

/* ============= ------------------ ============= */

actual fun createJWKCatching(parameters: JsonObject): Result<JWK> {
    return createJose4jJWKCatching(parameters)
}

/* ============= ------------------ ============= */

actual fun String.decodeJWKCatching(): Result<JWK> {
    return decodeJose4jJWKCatching()
}

/* ============= ------------------ ============= */
