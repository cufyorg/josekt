package org.cufy.jose.internal

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

@OptIn(ExperimentalEncodingApi::class)
internal val BASE_64_URL_SAFE_PRESENT_OPTIONAL =
    Base64.UrlSafe.withPadding(Base64.PaddingOption.PRESENT_OPTIONAL)
