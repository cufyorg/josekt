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
import kotlin.Result.Companion.failure
import kotlin.Result.Companion.success

/* ============= ------------------ ============= */

actual fun JWT.signCatching(jwks: JWKSet, defaultConstraints: Boolean): Result<CompactJWS> {
    val kid = header["kid"]?.asStringOrNull
    val alg = header["alg"]?.asStringOrNull

    if (alg == "none")
        return jose4j_signCatching(defaultConstraints)

    val jwk = jwks.findSign(kid, alg)
    jwk ?: return failure(IllegalArgumentException("jws signing failed: no matching key: kid=$kid; alg=$alg"))

    return when (jwk) {
        is Jose4jJWK -> jose4j_signCatching(jwk, defaultConstraints)
    }
}

/* ============= ------------------ ============= */

actual fun CompactJWS.verifyCatching(jwks: JWKSet, defaultConstraints: Boolean): Result<Boolean> {
    val h = this.decodedHeaderOrNull

    val kid = h?.get("kid")?.asStringOrNull
    val alg = h?.get("alg")?.asStringOrNull

    if (alg == "none") {
        if (defaultConstraints)
            return failure(IllegalArgumentException("jws verification failed: algorithm 'none' is not allowed"))

        return success(true)
    }

    val jwk = jwks.findVerify(kid, alg)
    jwk ?: return failure(IllegalArgumentException("jws verification failed: no matching key: kid=$kid; alg=$alg"))

    return when (jwk) {
        is Jose4jJWK -> jose4j_verifyCatching(jwk, defaultConstraints)
    }
}

/* ============= ------------------ ============= */

actual fun CompactJWS.verifiedCatching(jwks: Set<JWK>, defaultConstraints: Boolean): Result<JWT> {
    val h = this.decodedHeaderOrNull

    val kid = h?.get("kid")?.asStringOrNull
    val alg = h?.get("alg")?.asStringOrNull

    if (alg == "none") {
        if (defaultConstraints)
            return failure(IllegalArgumentException("jws verification failed: algorithm 'none' is not allowed"))

        return unverifiedCatching()
    }

    val jwk = jwks.findVerify(kid, alg)
    jwk ?: return failure(IllegalArgumentException("jws verification failed: no matching key: kid=$kid; alg=$alg"))

    return when (jwk) {
        is Jose4jJWK -> jose4j_verifiedCatching(jwk, defaultConstraints)
    }
}

/* ============= ------------------ ============= */

actual fun CompactJWS.unverifiedCatching(): Result<JWT> {
    return jose4j_unverifiedCatching()
}

/* ============= ------------------ ============= */
