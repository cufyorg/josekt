package org.cufy.jose.test

// language=json
const val JWKS_0 = """
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "-O4Ur3EdjSdevnsO",
      "use": "sig",
      "n": "z7wr7KU0oGrpHLAbe1eic-uJ6XgwVWYfmkpPHCuG5-HRIxW6qUMjXN7SHL8nDjMTx14OZfSqhfaJd0jkkuuIg9hsCxDSzelWxJiWRoVMA3fPO6kFmac_VWxTv2hjVMF0IBClhr_vgxIzeLRn1Hb-kACtMNb1ajMtovC9SqA7QxKbFjExVHqOxkgbAnx3BQSEYDpKjBa1a3JBLyweZqW1q_yqcElG0376l22YUQbchBN5sg-TE7enyQzQbl8oztxb7wgOOZRSRlLickiF8cWPeWO3WX1Is2eIM6E8vaHPSTsRnjuy0PbCjF89biCMzo0GfMeZGppL-bu24JcnJZFxNw",
      "e": "AQAB",
      "d": "B2pkuQRmvglC_BKvUHZe5rt0R2DSfOHx49yeOVe2b6WohROb_7nVU9Xic0NBniilnprVcb9LrQ-RdbAk9Leyvl4l8TkvBUm8nrUBvE-62G7Y93y_pe4J_T8qOC1-SkLDpfdiKU7FuoyWSMtL35JF4RcdF5680Qc1rFjisPzKUMkTPP3vgfzLOmhvAuq2U0zcUXXu8bK3bdEMaghl66_m6KuBmCXlakVMTy-tH0nhZGcC1TUQ6wRnK6opYNlDStsNMWBBLyolr0Gk16ulVYcnRGUGIp9z-eYPM5f4v3v_wWloRA7iM9JAnCCwp5wMPJhTtOHS0nqLpJZ3sbI5gU0pEQ",
      "p": "1lHtoKYn98Buq4k25ZTzXmZF_XodWFS6M41YRhLU31yNb3jIdBuQQaQf9Z0tRTp8dL1cxoEtaQCUVxS3ij6DNbHX8E50iG1uVwaYVxmyJ6xtf772Z6fTn1UWtYQUYp5e_-EvKFd-mHIIDE3QMfnQhJJgXjkwCsJ8wl-jiXCEyNE",
      "q": "-CJnuu1tiiSwhO_5N7U0Cr_EcCBmjlOP0HRhxkNP3oJhk_edGkOlIBXUFdJTFnaS_-X9591oB4QZKPnyc2H4FYFBkEbJP-1twLsh0ghVaUXKOZymp_8LchJVv3lf_KA6Q83iVDtgJzdcMc4BCdc_BMPh34g_gs0zb0LAmhflm4c",
      "dp": "TcGBphRCUeeV_1QT_61PsoMGh5UjSmXK_GMekKXKZ5MrmTLH_x_08Wu7UKAKyaATgUMmgrphIERejU1t3ZEah4OTZZMBQnH5Y0d4Q7mF4lDzlTJSMX85DwiO6aIWx0TQEKPBOTCtNF_CvbwJeeg5l6-HmQfEf1LacqbCLV4OPtE",
      "dq": "nNiSnRQLk7DRa5aM_-uoc8r4DrBMY1bqpyeJzlsqF0pvB6sTQVDVBc0GfKywHJjjHqJwtqm7YlTb2ozz9n9M47sKiHpWJ_Sa1aL0I-Fkq-CTjYs5xSNwRrDURu4gAH3_lnCDyh6mDuPtgQXoniHTEd4H3tYu3y16f6_AMyc72e0",
      "qi": "U1YAYPelSyru8gXEIWXY--2fDg9mRjxn8wk3lA0ixFwmG2j-H2w6Cuk2s_IMuV2c0X9C8osnwG61BV0tRC4UGEO8TAuFm49xlo0OG_7fnAZABi9n0VzlHT68Cd8FD3bgswCcFdKDF6vCYbqk3wg6eCRsq-h8fq56_w48O2_8Tfs"
    },
    {
      "kty": "RSA",
      "kid": "l2HxCMe1OG5ZCQeR",
      "use": "enc",
      "n": "mrKd3Y3aLI_MCVRO1aWDJceTzp2k_u8qF9tijNl70kzmG-8omdJljD1Z84oCwu0us8Wd8NMi8S9cGVKbV6C74S2_6y6h4O3MCK8VR24MqNfieqH7h8GF-tg3vStCpxlPtaL7AtIbN-12ygo94_Zu8ecHiur4i2Yly0U-O9MNS18mfsA9tBQmEjHbF5EwO02V24HvK8JpMtkAHa3wRz8XXAETn_TGm-QAwPKEuQxNmvxI1SKvz_0CCuPFsmayNdW8vHtrcIOmF1HU1NamUT2MAxan7L5hM8THKy28cSXN6_tItzDMixZIc0ZXLf8Vs2pBoLYmLU6m8XqKiqq-Q3QTkQ",
      "e": "AQAB",
      "d": "DUFTzImckafqnDwImz7Y23Jb5F7Wpe95RF0MdzQla3IiX29hI7kG8XrKS9deADTRhR7gNyPoQRFFS3gsDlib8KH6aVzwCvVlP7M82AeCdy80XTym8E1xPPqs3_0mc2n0TgR-jJHTOjoTLSGuhut1Oy4IE-upS0x_3Yh72iVt5LDK24Q39SFqGMo8OfDPmx8AIJVyoYOTlF6FZiMHd1Bop5W6rxmJzsjU-22aEuhE1jNPKBj0OLT2FviwQOLd2Ev8XnRM9hQKvZLkgIJWGoJwI9L62hSCRFa05AK8QK-UPp_hjlyYH-zD-LxUw5Zz1BDSheJmkpS9RGzMKO3wRS5szw",
      "p": "zpGeCAvEezqt9VCHsyZZrxgevjKXMr8BGl2WaixXyGbB3H3iAlaYDCNtVttzbJaofvCsTRvbjQmtnmxuy_vImMljKXt6emX2-gM4-7szFpyDPeZXKm0F7DmlAiIfqUvHLlJOl8uu7fBW2Ao-N1PnkuTnTZq2lmRsa2HhPDo8F6c",
      "q": "v7dhvODv_YeECJlJptf5StNFgO_EqHKy9XiXGPOW6ky8XYDXQXDfYBPRSdVgLdWR7obXnEYp8hn_sCvFw8E0ebQbaDYLWCihTsbRobQU3mDNsMZnYWh-SsLecbaVxYUM0hpiw97jJxxfDP2hwjLlSRu6lYNr9w9MI_Vhzwdi4gc",
      "dp": "tZlg0_P8bNVef26njcCmUX8j79OsBsnSX2ptRLPtDFoCDiSA38te6jTu98__fjRItyhAYZ2e-zPJ9Z-gHCYi6OcLDTnnp9kiMhNJMk0VkchQvMdWVA76iPz4apKzQPNEjR2AyIQhKj8DKfR_U8aorAQesKPV5wssIY8wIvGTSLs",
      "dq": "jflq6uoVL8Zsk8WY0nK8TZo5rWtiUnBmcPx1wOebSjW7hO8F-ZNyCH-EjM30ZNz1LhQzlaosI_r26-rukLICf2JOrZTgP9AO7Py1f6-RiMFdcdzr8Cnm5Mx82O8i6NxIC0u4-l6UD4GmLkOhx-PTApoDSffCO3rbowF0BlHs-38",
      "qi": "UCttt6xvPvFwG_GIF9-dpe6XpKmrm5D2CvsWJ8Nj1jCeeFDuPuRdQ-W2cuK4EkSuRhzdng-Z2Y-U67FpRmw1dLoJ8QoXC3bM4KKICss-tzrNPZLRSMF2M_jRg2cZFqRw6R3MRxWofJ9YXznL30_S36t8k7Xd7ckl4O7yMh3HZEc"
    },
    {
      "kty": "EC",
      "kid": "NSp_nvFRCYkSeBMq",
      "use": "sig",
      "x": "d9Ds-PnlY28EuK8y6QoG87nZ94Je7-JgSsd7_r3Y7WnhZrc7qjSbwixk9q3MmgI5",
      "y": "qSaziFrqnLJbPC61SVhM46IV5oQ5hOuNQ3BvBgbe3u25Mp1kYn0BMkDsDVkRNgfJ",
      "crv": "P-384",
      "d": "8pyFWVxNTAaZGCRMoxNFo2tQoWcqMIJbm79_aUxOCQpFnsC7v5iVi8-UEqtnWinC"
    },
    {
      "kty": "EC",
      "kid": "44D5W9RiEx43WJPC",
      "use": "enc",
      "x": "su5MNyMeXt60EOnOEEQvs5ylq_ixbu2SiiQqrnE4acwZ08z5jy_Ey0pU0VXBg2Aj",
      "y": "merrD3BirNLDA19Dm6koY3zU95v8LMFIYfiycgTuwG5YemQKNPk-vIuHXwu8tuJj",
      "crv": "P-384",
      "d": "Qb4AcHiwFeHERNXXsEHR-KTVWDKLRS54MRVhoTNCbE_UvUrb3oJUiuaVIAHZ-IuO"
    }
  ]
}

"""
