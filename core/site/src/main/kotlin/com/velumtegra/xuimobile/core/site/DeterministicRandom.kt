package com.velumtegra.xuimobile.core.site

internal object StableSeedHash {
    private const val FNV_OFFSET_BASIS: ULong = 14695981039346656037uL
    private const val FNV_PRIME: ULong = 1099511628211uL

    fun derive(seed: Long, namespace: String): Long {
        var hash = FNV_OFFSET_BASIS xor seed.toULong()
        namespace.encodeToByteArray().forEach { byte ->
            hash = (hash xor byte.toUByte().toULong()) * FNV_PRIME
        }
        return mix64(hash.toLong())
    }

    private fun mix64(input: Long): Long {
        var z = input
        z = (z xor (z ushr 30)) * -4658895280553007687L
        z = (z xor (z ushr 27)) * -7723592293110705685L
        return z xor (z ushr 31)
    }
}

internal class DeterministicRandom(seed: DesignSeed) {
    private var state: Long = seed.value

    fun nextLong(): Long {
        state += -7046029254386353131L
        var z = state
        z = (z xor (z ushr 30)) * -4658895280553007687L
        z = (z xor (z ushr 27)) * -7723592293110705685L
        return z xor (z ushr 31)
    }

    fun nextInt(bound: Int): Int {
        require(bound > 0)
        return ((nextLong().ushr(1) % bound.toLong()).toInt())
    }

    fun nextInt(minInclusive: Int, maxInclusive: Int): Int {
        require(minInclusive <= maxInclusive)
        return minInclusive + nextInt(maxInclusive - minInclusive + 1)
    }


    fun <T> choose(values: List<T>): T = values[nextInt(values.size)]
}
