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

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import org.jose4j.jwk.JsonWebKey
import org.jose4j.lang.JoseException
import kotlin.Result.Companion.failure
import kotlin.Result.Companion.success

/* ============= ------------------ ============= */

data class Jose4jJWK(
    val java: JsonWebKey,
    override val parameters: JsonObject,
) : JWK {
    override val publicParameters by lazy {
        java.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)
            .jose4j_toJsonElementCatching()
            .getOrThrow()
    }

    override val kty: String = java.keyType
    override val use: String? = java.use
    override val kid: String? = java.keyId
    override val alg: String? = java.algorithm
    override val keyOps: List<String>? = java.keyOps
}

/* ============= ------------------ ============= */

fun createJose4jJWKCatching(parameters: JsonObject): Result<Jose4jJWK> {
    val parametersJava = parameters.jose4j_toJavaObjectCatching().getOrElse { return failure(it) }
    val java = try {
        JsonWebKey.Factory.newJwk(parametersJava)
    } catch (e: JoseException) {
        return failure(e)
    }
    return success(Jose4jJWK(java, parameters))
}

/* ============= ------------------ ============= */

fun String.decodeJose4jJWKCatching(): Result<Jose4jJWK> {
    val parameters = try {
        Json.parseToJsonElement(this)
    } catch (e: SerializationException) {
        return failure(e)
    }

    if (parameters !is JsonObject)
        return failure(IllegalArgumentException("Bad JWK. Expected JsonObject"))

    return createJose4jJWKCatching(parameters)
}

/* ============= ------------------ ============= */
