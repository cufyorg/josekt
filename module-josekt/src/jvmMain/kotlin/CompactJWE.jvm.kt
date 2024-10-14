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

/* ============= ------------------ ============= */

actual fun JWT.encryptCatching(jwks: JWKSet, defaultConstraints: Boolean): Result<CompactJWE> {
    val kid = header["kid"]?.asStringOrNull
    val alg = header["alg"]?.asStringOrNull

    val jwk = jwks.findEncrypt(kid, alg)
    jwk ?: return failure(IllegalArgumentException("jwe encryption failed: no matching key: kid=$kid; alg=$alg"))

    return when (jwk) {
        is Jose4jJWK -> jose4j_encryptCatching(jwk, defaultConstraints)
    }
}

/* ============= ------------------ ============= */

actual fun CompactJWE.decryptCatching(jwks: Set<JWK>, defaultConstraints: Boolean): Result<JWT> {
    val h = this.decodedHeaderOrNull

    val kid = h?.get("kid")?.asStringOrNull
    val alg = h?.get("alg")?.asStringOrNull

    val jwk = jwks.findEncrypt(kid, alg)
    jwk ?: return failure(IllegalArgumentException("jwe decryption failed: no matching key: kid=$kid; alg=$alg"))

    return when (jwk) {
        is Jose4jJWK -> jose4j_decryptCatching(jwk, defaultConstraints)
    }
}

/* ============= ------------------ ============= */
