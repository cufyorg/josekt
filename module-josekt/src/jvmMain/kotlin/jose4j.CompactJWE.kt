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
import org.jose4j.jwe.JsonWebEncryption
import kotlin.Result.Companion.failure

/* ============= ------------------ ============= */

@Suppress("FunctionName")
internal fun JWT.jose4j_encryptCatching(jwk: Jose4jJWK, defaultConstraints: Boolean): Result<CompactJWE> {
    val alg = header["alg"]?.asStringOrNull
        ?: defaultEncAlg(jwk.kty, jwk.use, jwk.alg)
    val enc = header["enc"]?.asStringOrNull
        ?: defaultEncEnc(jwk.kty, jwk.use, jwk.alg)

    val jose4j = JsonWebEncryption()
    if (!defaultConstraints) {
        jose4j.setAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS)
        jose4j.setContentEncryptionAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS)
    }
    jose4j.applyCatching(this).onFailure { return failure(it) }
    jose4j.key = jwk.java.key
    jose4j.setHeader("kid", jwk.kid)
    jose4j.setHeader("alg", alg)
    jose4j.setHeader("enc", enc)

    return jose4j.encryptToCompactJWECatching()
}

/* ============= ------------------ ============= */

@Suppress("FunctionName")
internal fun CompactJWE.jose4j_decryptCatching(jwk: Jose4jJWK, defaultConstraints: Boolean): Result<JWT> {
    val jose4j = JsonWebEncryption()
    if (!defaultConstraints) {
        jose4j.setAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS)
        jose4j.setContentEncryptionAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS)
    }
    jose4j.applyCatching(this).onFailure { return failure(it) }
    jose4j.key = jwk.java.key

    return jose4j.toJWTCatching()
}

/* ============= ------------------ ============= */
