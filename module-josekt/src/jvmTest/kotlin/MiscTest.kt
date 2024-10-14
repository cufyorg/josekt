package org.cufy.jose.test

import org.cufy.jose.*
import org.cufy.jose.internal.set
import kotlin.test.Test
import kotlin.test.assertEquals

class MiscTest {
    @Test
    fun `simple JWS signing test 0`() {
        val jwks = JWKS_0.decodeJWKSet()
        val jwt = JWT {
            header["typ"] = "jwt"
            header["alg"] = "RS256"
            payload["sub"] = "lsafer"
        }

        val expectedJwt = JWT {
            header["typ"] = "jwt"
            header["alg"] = "RS256"
            header["kid"] = "-O4Ur3EdjSdevnsO"
            payload["sub"] = "lsafer"
        }
        val expectedCompact = CompactJWS(
            header = "eyJ0eXAiOiJqd3QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ii1PNFVyM0VkalNkZXZuc08ifQ",
            payload = "eyJzdWIiOiJsc2FmZXIifQ",
            signature = "J4KsOgOD80N8kpuN8ph5-3Ki0hEIeNtG6eQNcb1Qo9oRksim423-0Sr6AHgmsWxjxBn8kjtiL8EhwPNgsiaPQuSg-6qvzp5eUnm2j3EoHnFE7LeBVPFNll-4LdjU5NC2k0jAPIQ-bqGDTLrRnQp_FzKn11WUcetnDj1BxOlBhC9TKfBWt88wiCyRcB742JSiDjy08ARdXNLsKSm6SoHJAr4hK_KRmKlyu4gO1y_d6bOYfLZrxyfn_PdhFBmbX3089R9cCDLuzI20vWetkJuchOLF_kyWb8U1OFhQffwQ7uJpV48cKmUjhgKpeXxpkkdqI9iZxFgS4FYhr6VwOLso2A",
        )

        val actualCompact = jwt.sign(jwks)

        assertEquals(expectedCompact, actualCompact)

        val actualJwt = actualCompact.verified(jwks)

        assertEquals(expectedJwt, actualJwt)

        // verify that unverified() does not fail
        actualCompact.unverified()
    }
}
