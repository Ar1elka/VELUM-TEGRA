package com.velumtegra.xuimobile.core.webpanel

/** Minimal strict JSON reader used only for bounded 3X-UI response envelopes. */
internal object BoundedJson {
    sealed interface Value {
        data class Obj(val fields: Map<String, Value>) : Value
        data class Arr(val values: List<Value>) : Value
        data class Str(val value: String) : Value
        data class Num(val value: String) : Value
        data class Bool(val value: Boolean) : Value
        data object Null : Value
    }

    fun parseObject(text: String): Value.Obj? = runCatching { Parser(text).parseRootObject() }.getOrNull()

    private class Parser(private val text: String) {
        private var index = 0
        private var depth = 0

        fun parseRootObject(): Value.Obj {
            skipSpace()
            val value = parseValue()
            skipSpace()
            check(index == text.length) { "Trailing JSON data" }
            return value as? Value.Obj ?: error("Expected JSON object")
        }

        private fun parseValue(): Value {
            skipSpace()
            check(index < text.length) { "Unexpected JSON end" }
            return when (text[index]) {
                '{' -> parseObject()
                '[' -> parseArray()
                '"' -> Value.Str(parseString())
                't' -> { expectLiteral("true"); Value.Bool(true) }
                'f' -> { expectLiteral("false"); Value.Bool(false) }
                'n' -> { expectLiteral("null"); Value.Null }
                '-', in '0'..'9' -> Value.Num(parseNumber())
                else -> error("Invalid JSON value")
            }
        }

        private fun parseObject(): Value.Obj = nested {
            expect('{')
            skipSpace()
            val fields = LinkedHashMap<String, Value>()
            if (peek('}')) {
                index++
                return@nested Value.Obj(fields)
            }
            while (true) {
                skipSpace()
                check(peek('"')) { "Expected JSON object key" }
                val key = parseString()
                check(!fields.containsKey(key)) { "Duplicate JSON key" }
                skipSpace()
                expect(':')
                fields[key] = parseValue()
                skipSpace()
                when {
                    peek(',') -> index++
                    peek('}') -> {
                        index++
                        return@nested Value.Obj(fields)
                    }
                    else -> error("Expected object separator")
                }
            }
            error("Unreachable")
        }

        private fun parseArray(): Value.Arr = nested {
            expect('[')
            skipSpace()
            val values = mutableListOf<Value>()
            if (peek(']')) {
                index++
                return@nested Value.Arr(values)
            }
            while (true) {
                values += parseValue()
                skipSpace()
                when {
                    peek(',') -> index++
                    peek(']') -> {
                        index++
                        return@nested Value.Arr(values)
                    }
                    else -> error("Expected array separator")
                }
            }
            error("Unreachable")
        }

        private inline fun <T> nested(block: () -> T): T {
            depth++
            check(depth <= MAX_DEPTH) { "JSON nesting too deep" }
            return try {
                block()
            } finally {
                depth--
            }
        }

        private fun parseString(): String {
            expect('"')
            val out = StringBuilder()
            while (index < text.length) {
                val ch = text[index++]
                when {
                    ch == '"' -> return out.toString()
                    ch == '\\' -> out.append(parseEscape())
                    ch.code < 0x20 -> error("Control character in JSON string")
                    else -> out.append(ch)
                }
                check(out.length <= MAX_STRING_CHARS) { "JSON string too large" }
            }
            error("Unterminated JSON string")
        }

        private fun parseEscape(): Char {
            check(index < text.length) { "Invalid JSON escape" }
            return when (val escaped = text[index++]) {
                '"', '\\', '/' -> escaped
                'b' -> '\b'
                'f' -> '\u000c'
                'n' -> '\n'
                'r' -> '\r'
                't' -> '\t'
                'u' -> parseUnicodeEscape()
                else -> error("Invalid JSON escape")
            }
        }

        private fun parseUnicodeEscape(): Char {
            check(index + 4 <= text.length) { "Short unicode escape" }
            val hex = text.substring(index, index + 4)
            check(hex.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) { "Bad unicode escape" }
            index += 4
            return hex.toInt(16).toChar()
        }

        private fun parseNumber(): String {
            val start = index
            if (peek('-')) index++
            check(index < text.length) { "Invalid JSON number" }
            if (peek('0')) {
                index++
            } else {
                check(text[index] in '1'..'9') { "Invalid JSON number" }
                while (index < text.length && text[index].isDigit()) index++
            }
            if (peek('.')) {
                index++
                check(index < text.length && text[index].isDigit()) { "Invalid JSON fraction" }
                while (index < text.length && text[index].isDigit()) index++
            }
            if (index < text.length && (text[index] == 'e' || text[index] == 'E')) {
                index++
                if (index < text.length && (text[index] == '+' || text[index] == '-')) index++
                check(index < text.length && text[index].isDigit()) { "Invalid JSON exponent" }
                while (index < text.length && text[index].isDigit()) index++
            }
            return text.substring(start, index)
        }

        private fun expectLiteral(value: String) {
            check(text.regionMatches(index, value, 0, value.length)) { "Invalid JSON literal" }
            index += value.length
        }

        private fun expect(ch: Char) {
            check(index < text.length && text[index] == ch) { "Expected '$ch'" }
            index++
        }

        private fun peek(ch: Char): Boolean = index < text.length && text[index] == ch

        private fun skipSpace() {
            while (index < text.length && text[index] in JSON_SPACE) index++
        }
    }

    private val JSON_SPACE = setOf(' ', '\t', '\n', '\r')
    private const val MAX_DEPTH = 8
    private const val MAX_STRING_CHARS = 64 * 1024
}
