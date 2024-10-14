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

import kotlinx.datetime.Instant
import org.cufy.jose.internal.*
import org.cufy.jose.internal.asStringOrNull

// @formatter:off

// JWS https://datatracker.ietf.org/doc/html/rfc7515
// JWE https://datatracker.ietf.org/doc/html/rfc7516
// JWS: alg         jku jwk kid x5u x5c x5t x5t#S256 typ cty crit
// JWE: alg enc zip jku jwk kid x5u x5c x5t x5t#S256 typ cty crit

val CompactJWT.alg: String? get() = decodedHeaderOrNull?.get("alg")?.asStringOrNull
val CompactJWT.jku: String? get() = decodedHeaderOrNull?.get("jku")?.asStringOrNull
//val CompactJWT.jwk: String? get() = decodedHeaderOrNull?.get("jwk")?.asStringOrNull
val CompactJWT.kid: String? get() = decodedHeaderOrNull?.get("kid")?.asStringOrNull
//val CompactJWT.x5u: String? get() = decodedHeaderOrNull?.get("x5u")?.asStringOrNull
//val CompactJWT.x5c: String? get() = decodedHeaderOrNull?.get("x5c")?.asStringOrNull
//val CompactJWT.x5t: String? get() = decodedHeaderOrNull?.get("x5t")?.asStringOrNull
//val CompactJWT.x5t_s256: String? get() = decodedHeaderOrNull?.get("x5t#S256")?.asStringOrNull
val CompactJWT.typ: String? get() = decodedHeaderOrNull?.get("typ")?.asStringOrNull
val CompactJWT.cty: String? get() = decodedHeaderOrNull?.get("cty")?.asStringOrNull
val CompactJWT.crit: List<String>? get() = decodedHeaderOrNull?.get("crit")?.asStringListOrNull

val CompactJWE.enc: String? get() = decodedHeaderOrNull?.get("enc")?.asStringOrNull
val CompactJWE.zip: String? get() = decodedHeaderOrNull?.get("zip")?.asStringOrNull

val JWT.alg: String? get() = header["alg"]?.asStringOrNull
val JWT.jku: String? get() = header["jku"]?.asStringOrNull
//val JWT.jwk: String? get() = header["jwk"]?.asStringOrNull
val JWT.kid: String? get() = header["kid"]?.asStringOrNull
//val JWT.x5u: String? get() = header["x5u"]?.asStringOrNull
//val JWT.x5c: String? get() = header["x5c"]?.asStringOrNull
//val JWT.x5t: String? get() = header["x5t"]?.asStringOrNull
//val JWT.x5t_s256: String? get() = header["x5t#S256"]?.asStringOrNull
val JWT.typ: String? get() = header["typ"]?.asStringOrNull
val JWT.cty: String? get() = header["cty"]?.asStringOrNull
val JWT.crit: List<String>? get() = header["crit"]?.asStringListOrNull
val JWT.enc: String? get() = header["enc"]?.asStringOrNull
val JWT.zip: String? get() = header["zip"]?.asStringOrNull

// JWT https://datatracker.ietf.org/doc/html/rfc7519
// JWT: iss sub aud exp nbf iat jti

val CompactJWS.iss: String? get() = decodedPayloadOrNull?.get("iss")?.asStringOrNull
val CompactJWS.sub: String? get() = decodedPayloadOrNull?.get("sub")?.asStringOrNull
val CompactJWS.aud: List<String>? get() = decodedPayloadOrNull?.get("aud")?.asStringListCoerceOrNull
val CompactJWS.exp: Instant? get() = decodedPayloadOrNull?.get("exp")?.asInstantOrNull
val CompactJWS.nbf: Instant? get() = decodedPayloadOrNull?.get("nbf")?.asInstantOrNull
val CompactJWS.iat: Instant? get() = decodedPayloadOrNull?.get("iat")?.asInstantOrNull
val CompactJWS.jti: String? get() = decodedPayloadOrNull?.get("jti")?.asStringOrNull

val JWT.iss: String? get() = decodedPayloadOrNull?.get("iss")?.asStringOrNull
val JWT.sub: String? get() = decodedPayloadOrNull?.get("sub")?.asStringOrNull
val JWT.aud: List<String>? get() = decodedPayloadOrNull?.get("aud")?.asStringListCoerceOrNull
val JWT.exp: Instant? get() = decodedPayloadOrNull?.get("exp")?.asInstantOrNull
val JWT.nbf: Instant? get() = decodedPayloadOrNull?.get("nbf")?.asInstantOrNull
val JWT.iat: Instant? get() = decodedPayloadOrNull?.get("iat")?.asInstantOrNull
val JWT.jti: String? get() = decodedPayloadOrNull?.get("jti")?.asStringOrNull

//

val CompactJWS.client_id: String? get() = decodedPayloadOrNull?.get("client_id")?.asStringOrNull

val JWT.client_id: String? get() = decodedPayloadOrNull?.get("client_id")?.asStringOrNull
