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

/* ============= ------------------ ============= */

open class JWTBuilder {
    val header: MutableMap<String, JsonElement> = mutableMapOf()
    val payload: MutableMap<String, JsonElement> = mutableMapOf()

    fun build(): JWT {
        return JWT(
            header = JsonObject(this.header.toMap()),
            payload = Json.encodeToString(this.payload),
        )
    }
}

/**
 * Construct a new [JWT] using the given builder [block].
 */
inline fun JWT(block: JWTBuilder.() -> Unit): JWT {
    return JWTBuilder().apply(block).build()
}

/**
 * Create a copy of this JWT, apply [block] to it, and return it.
 *
 * @throws IllegalArgumentException if the payload cannot be decoded as json.
 */
inline fun JWT.append(block: JWTBuilder.() -> Unit): JWT {
    val payload = requireNotNull(this.decodedPayloadOrNull) {
        "jwt.decodedPayloadOrNull was null thus cannot append it as json."
    }

    val builder = JWTBuilder()
    builder.header += this.header
    builder.payload += payload
    return builder.build()
}

/* ============= ------------------ ============= */
