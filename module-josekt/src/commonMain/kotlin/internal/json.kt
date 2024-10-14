package org.cufy.jose.internal

import kotlinx.datetime.Instant
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.*

internal inline val JsonPrimitive.stringOrNull get() = if (isString) content else null
internal inline val JsonElement.asJsonPrimitiveOrNull: JsonPrimitive? get() = this as? JsonPrimitive
internal inline val JsonElement.asStringOrNull: String? get() = asJsonPrimitiveOrNull?.stringOrNull
internal inline val JsonElement.asJsonObjectOrNull: JsonObject? get() = this as? JsonObject
internal inline val JsonElement.asJsonObject: JsonObject get() = this as JsonObject
internal inline val JsonElement.asJsonArrayOrNull: JsonArray? get() = this as? JsonArray
internal inline val JsonElement.asLongOrNull: Long? get() = asJsonPrimitiveOrNull?.longOrNull

internal fun String.decodeJsonOrNull(json: Json = Json): JsonElement? {
    return try {
        json.parseToJsonElement(this)
    } catch (_: SerializationException) {
        return null
    }
}

internal val JsonElement.asStringListOrNull: List<String>?
    get() = asJsonArrayOrNull?.map { it.asStringOrNull ?: return null }

internal val JsonElement.asStringListCoerceOrNull: List<String>?
    get() = if (this is JsonArray) map { it.asStringOrNull ?: return null }
    else asStringOrNull?.let { listOf(it) }

internal val JsonElement.asInstantOrNull: Instant?
    get() = asLongOrNull?.let { Instant.fromEpochSeconds(it) }

internal operator fun MutableMap<String, JsonElement>.set(name: String, value: String?) {
    val element = JsonPrimitive(value)
    this[name] = element
}
