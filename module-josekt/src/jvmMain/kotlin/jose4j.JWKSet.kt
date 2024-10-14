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
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.lang.JoseException
import kotlin.Result.Companion.failure
import kotlin.Result.Companion.success

/* ============= ------------------ ============= */

typealias Jose4jJWKSet = Set<Jose4jJWK>

/* ============= ------------------ ============= */

fun String.decodeJose4jJWKSetCatching(): Result<Jose4jJWKSet> {
    val parametersJavaSet = try {
        JsonWebKeySet(this).jsonWebKeys
    } catch (e: JoseException) {
        return failure(e)
    }
    val parametersSet = try {
        Json.parseToJsonElement(this)
    } catch (e: SerializationException) {
        return failure(e)
    }

    if (parametersSet !is JsonObject)
        return failure(IllegalArgumentException("Bad JWKSet. Expected JsonObject"))

    val parametersSetKeys = parametersSet["keys"]

    if (parametersSetKeys !is JsonArray)
        return failure(IllegalArgumentException("Bad JWKSet keys. Expected JsonArray"))

    val count = parametersSetKeys.size
    return success(buildSet(count) {
        for (i in 0..<count) {
            val parametersJava = parametersJavaSet[i]
            val parameters = parametersSetKeys[i]

            if (parameters !is JsonObject)
                return failure(IllegalArgumentException("Bad JWK. Expected JsonObject"))

            this += Jose4jJWK(parametersJava, parameters)
        }
    })
}

/* ============= ------------------ ============= */
