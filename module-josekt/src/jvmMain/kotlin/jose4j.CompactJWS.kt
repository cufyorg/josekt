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

import org.cufy.jose.internal.asStringOrNull
import org.jose4j.jwa.AlgorithmConstraints
import org.jose4j.jwk.PublicJsonWebKey
import org.jose4j.jws.JsonWebSignature
import org.jose4j.lang.JoseException
import kotlin.Result.Companion.failure
import kotlin.Result.Companion.success

/* ============= ------------------ ============= */

@Suppress("FunctionName")
internal fun JWT.jose4j_signCatching(defaultConstraints: Boolean): Result<CompactJWS> {
    val alg = header["alg"]?.asStringOrNull

    val jose4j = JsonWebSignature()
    if (!defaultConstraints) {
        jose4j.setAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS)
    }
    jose4j.applyCatching(this).onFailure { return failure(it) }
    jose4j.setHeader("alg", alg)

    return jose4j.signToCompactJWSCatching()
}

@Suppress("FunctionName")
internal fun JWT.jose4j_signCatching(jwk: Jose4jJWK, defaultConstraints: Boolean): Result<CompactJWS> {
    if (jwk.java !is PublicJsonWebKey)
        return failure(IllegalArgumentException("jwt signing failed: key is not an asymmetric key"))

    val alg = header["alg"]?.asStringOrNull
        ?: defaultSigAlg(jwk.kty, jwk.use, jwk.alg)

    val jose4j = JsonWebSignature()
    if (!defaultConstraints) {
        jose4j.setAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS)
    }
    jose4j.applyCatching(this).onFailure { return failure(it) }
    jose4j.key = jwk.java.privateKey
    jose4j.setHeader("kid", jwk.kid)
    jose4j.setHeader("alg", alg)

    return jose4j.signToCompactJWSCatching()
}

/* ============= ------------------ ============= */

@Suppress("FunctionName")
internal fun CompactJWS.jose4j_verifyCatching(jwk: Jose4jJWK, defaultConstraints: Boolean): Result<Boolean> {
    val jose4j = JsonWebSignature()
    if (!defaultConstraints) {
        jose4j.setAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS)
    }
    jose4j.applyCatching(this).onFailure { return failure(it) }
    jose4j.key = jwk.java.key

    val isVerified = try {
        jose4j.verifySignature()
    } catch (e: JoseException) {
        return failure(e)
    }

    return success(isVerified)
}

/* ============= ------------------ ============= */

@Suppress("FunctionName")
internal fun CompactJWS.jose4j_verifiedCatching(jwk: Jose4jJWK, defaultConstraints: Boolean): Result<JWT> {
    val jose4j = JsonWebSignature()
    if (!defaultConstraints) {
        jose4j.setAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS)
    }
    jose4j.applyCatching(this).onFailure { return failure(it) }
    jose4j.key = jwk.java.key

    val isVerified = try {
        jose4j.verifySignature()
    } catch (e: JoseException) {
        return failure(e)
    }

    if (!isVerified)
        return failure(IllegalArgumentException("jws verification failed: invalid signature"))

    return jose4j.toJWTCatching()
}

/* ============= ------------------ ============= */

@Suppress("FunctionName")
internal fun CompactJWS.jose4j_unverifiedCatching(): Result<JWT> {
    val jose4j = JsonWebSignature()
    jose4j.setAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS)
    jose4j.applyCatching(this).onFailure { return failure(it) }
    val header = jose4j.headers.toJsonObject()
    val payload = jose4j.unverifiedPayload
    return success(JWT(header, payload))
}

/* ============= ------------------ ============= */
