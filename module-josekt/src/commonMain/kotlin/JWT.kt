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

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import org.cufy.jose.internal.asJsonObjectOrNull
import org.cufy.jose.internal.decodeJsonOrNull

/* ============= ------------------ ============= */

/**
 * The components of a decoded JWT.
 */
data class JWT(
    /**
     * The header claims.
     */
    val header: JsonObject,
    /**
     * The payload claims.
     */
    val payload: String,
) {
    /**
     * The decoded payload of the jwt.
     */
    val decodedPayloadOrNull by lazy {
        payload.decodeJsonOrNull()
            ?.asJsonObjectOrNull
    }
}

/* ============= ------------------ ============= */

/**
 * Return a [JWT] instance with [this] as its payload
 * and the given [headers] as its headers.
 */
fun JsonObject.toJWT(headers: JsonObject = JsonObject(emptyMap())): JWT {
    return JWT(header = headers, payload = Json.encodeToString(this))
}

/**
 * Return a [JWT] instance with [this] as its payload
 * and the result of the given [headers] block as its headers.
 */
inline fun JsonObject.toJWT(headers: MutableMap<String, JsonElement>.() -> Unit): JWT {
    return JWT(header = JsonObject(buildMap(headers)), payload = Json.encodeToString(this))
}

/* ============= ------------------ ============= */

/**
 * Return a [JWT] instance with [this] as its payload
 * and the given [headers] as its headers.
 */
fun String.toJWT(headers: JsonObject = JsonObject(emptyMap())): JWT {
    return JWT(header = headers, payload = this)
}

/**
 * Return a [JWT] instance with [this] as its payload
 * and the result of the given [headers] block as its headers.
 */
inline fun String.toJWT(headers: MutableMap<String, JsonElement>.() -> Unit): JWT {
    return JWT(header = JsonObject(buildMap(headers)), payload = this)
}

/* ============= ------------------ ============= */

/**
 * Return a [JWT] instance with [this] as its payload
 * and the given [headers] as its headers.
 */
fun CompactJWT.toNestedJWT(headers: JsonObject = JsonObject(emptyMap())): JWT {
    return JWT(header = headers, payload = value)
}

/**
 * Return a [JWT] instance with [this] as its payload
 * and the result of the given [headers] block as its headers.
 */
inline fun CompactJWT.toNestedJWT(headers: MutableMap<String, JsonElement>.() -> Unit): JWT {
    return JWT(header = JsonObject(buildMap(headers)), payload = value)
}

/* ============= ------------------ ============= */

fun JWT.headers(vararg headers: Pair<String, JsonElement>): JWT {
    return JWT(header = JsonObject(header + headers), payload = payload)
}

fun JWT.headers(headers: JsonObject = JsonObject(emptyMap())): JWT {
    return JWT(header = JsonObject(header + headers), payload = payload)
}

inline fun JWT.headers(block: MutableMap<String, JsonElement>.() -> Unit): JWT {
    return JWT(header = JsonObject(header + buildMap(block)), payload = payload)
}

/* ============= ------------------ ============= */
