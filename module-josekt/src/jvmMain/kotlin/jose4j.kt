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

import kotlinx.serialization.json.*
import org.cufy.jose.internal.asJsonObject
import org.jose4j.jwe.JsonWebEncryption
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwx.Headers
import org.jose4j.jwx.JsonWebStructure
import org.jose4j.lang.JoseException
import java.math.BigDecimal
import java.math.BigInteger
import kotlin.Result.Companion.failure
import kotlin.Result.Companion.success

/* ============= ------------------ ============= */

fun JsonWebStructure.applyCatching(jwt: JWT): Result<Unit> {
    this.headers.applyCatching(jwt.header).onFailure { return failure(it) }
    this.payload = jwt.payload
    return success(Unit)
}

fun JsonWebSignature.applyCatching(compact: CompactJWS): Result<Unit> {
    try {
        this.compactSerialization = compact.value
        return success(Unit)
    } catch (e: JoseException) {
        return failure(e)
    }
}

fun JsonWebEncryption.applyCatching(compact: CompactJWE): Result<Unit> {
    try {
        this.compactSerialization = compact.value
        return success(Unit)
    } catch (e: JoseException) {
        return failure(e)
    }
}

fun JsonWebStructure.toJWTCatching(): Result<JWT> {
    val header = this.headers.toJsonObject()
    val payload = this.payload
    return success(JWT(header, payload))
}

fun JsonWebSignature.signToCompactJWSCatching(): Result<CompactJWS> {
    val compactSerialization = try {
        compactSerialization
    } catch (e: JoseException) {
        return failure(e)
    }

    return compactSerialization.decodeCompactJWSCatching()
}

fun JsonWebEncryption.encryptToCompactJWECatching(): Result<CompactJWE> {
    val compactSerialization = try {
        compactSerialization
    } catch (e: JoseException) {
        return failure(e)
    }

    return compactSerialization.decodeCompactJWECatching()
}

/* ============= ------------------ ============= */

fun Headers.toJsonObject(): JsonObject {
    return fullHeaderAsJsonString
        .let { Json.parseToJsonElement(it) }
        .asJsonObject
}

fun Headers.applyCatching(element: JsonObject): Result<Unit> {
    for ((name, value) in element) {
        val valueJava = value.jose4j_toJavaObjectCatching().getOrElse { return failure(it) }

        setObjectHeaderValue(name, valueJava)
    }

    return success(Unit)
}

/* ============= ------------------ ============= */

@Suppress("FunctionName")
internal fun JsonObject.jose4j_toJavaObjectCatching(): Result<Map<String, *>> {
    return success(mapValues {
        it.value.jose4j_toJavaObjectCatching().getOrElse { return failure(it) }
    })
}

@Suppress("FunctionName")
internal fun JsonArray.jose4j_toJavaObjectCatching(): Result<List<*>> {
    return success(map {
        it.jose4j_toJavaObjectCatching().getOrElse { return failure(it) }
    })
}

@Suppress("FunctionName")
internal fun JsonElement.jose4j_toJavaObjectCatching(): Result<Any?> {
    return when (this) {
        is JsonNull -> success(null)
        is JsonPrimitive -> when {
            isString -> success(content)
            content == "true" -> success(true)
            content == "false" -> success(false)
            '.' in content -> runCatching { doubleOrNull ?: BigDecimal(content) }
            else -> runCatching { longOrNull ?: BigInteger(content) }
        }

        is JsonArray -> jose4j_toJavaObjectCatching()
        is JsonObject -> jose4j_toJavaObjectCatching()
    }
}

/* ============= ------------------ ============= */

@Suppress("FunctionName")
internal fun Map<*, *>.jose4j_toJsonElementCatching(): Result<JsonObject> {
    return success(JsonObject(entries.associate {
        "${it.key}" to it.value.jose4j_toJsonElementCatching().getOrElse { return failure(it) }
    }))
}

@Suppress("FunctionName")
internal fun List<*>.jose4j_toJsonElementCatching(): Result<JsonArray> {
    return success(JsonArray(map {
        it.jose4j_toJsonElementCatching().getOrElse { return failure(it) }
    }))
}

@Suppress("FunctionName")
internal fun Any?.jose4j_toJsonElementCatching(): Result<JsonElement> {
    return when (this) {
        null -> success(JsonNull)
        is CharSequence -> success(JsonPrimitive(toString()))
        is Boolean -> success(JsonPrimitive(this))
        is Number -> success(JsonPrimitive(this))
        is List<*> -> jose4j_toJsonElementCatching()
        is Map<*, *> -> jose4j_toJsonElementCatching()
        else -> failure(IllegalArgumentException("Couldn't convert ${this::class} to JsonElement"))
    }
}

/* ============= ------------------ ============= */
