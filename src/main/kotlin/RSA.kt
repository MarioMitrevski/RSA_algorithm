import java.math.BigInteger
import java.util.*
import kotlin.collections.ArrayList


object RSA {

    data class Keys(
        val publicKey: Pair<BigInteger, BigInteger>? = null,
        val privateKey: BigInteger? = null,
        val errorMessage: String? = null
    )

    /*
    *  @return GCD of a and b, s (parameter before a), t (parameter before b)
    */
    private fun gcdExtended(a: BigInteger, b: BigInteger): Triple<BigInteger, BigInteger, BigInteger> {
        if (a == BigInteger.ZERO) {
            return Triple(b, BigInteger.ZERO, BigInteger.ONE)
        }
        val triple = gcdExtended(b % a, a)
        val gcd = triple.first
        var s = triple.second
        val t = triple.third

        s = t - b / a * s
        return Triple(gcd, s, triple.second)
    }

    /*
    *  @return GCD of a and b, s (parameter before a), t (parameter before b)
    */
    private fun gcdExtended(a: Long, b: Long): Triple<Long, Long, Long> {
        if (a == 0L) {
            return Triple(b, 0, 1)
        }
        val triple = gcdExtended(b % a, a)
        val gcd = triple.first
        var s = triple.second
        val t = triple.third

        s = t - b / a * s
        return Triple(gcd, s, triple.second)
    }

    private fun phi(p: BigInteger, q: BigInteger): BigInteger = p.minus(BigInteger.ONE).times(q.minus(BigInteger.ONE))
    private fun phi(p: Long, q: Long): Long = p.minus(1).times(q.minus(1))

    private fun N(p: BigInteger, q: BigInteger): BigInteger = p.times(q)

    fun generateKeys(p: BigInteger, q: BigInteger): Keys {
        val phi = phi(p, q)
        val e = BigInteger("65537")

        val triple = gcdExtended(e, phi)
        val d = triple.second // Inverse of e

        return Keys(publicKey = Pair(N(p, q), e), privateKey = d)
    }

    fun encrypt(publicKey: Pair<BigInteger, BigInteger>, message: String): String {
        val messageBytes = BigInteger(message.encodeToByteArray())

        val N = publicKey.first
        val e = publicKey.second

        if (messageBytes < N) {
            val cipherText = messageBytes.modPow(e, N)
            val encodedCipher = Base64.getEncoder().encodeToString(cipherText.toByteArray())
            return encodedCipher
        } else {
            println(messageBytes)

            throw Exception("Message should be less than N!")
        }
    }

    fun decrypt(N: BigInteger, privateKey: BigInteger, cipherText: String): String {
        val decodedCipher = Base64.getDecoder().decode(cipherText)
        val originalMessage = BigInteger(decodedCipher).modPow(privateKey, N)
        return String(originalMessage.toByteArray(), charset("UTF-8"))
    }

    private fun factorizeN(N: Long): MutableList<Long> {
        var n = N
        val factors: MutableList<Long> = ArrayList()
        var b = 2
        for (i in 2..(n / b)) {
            while (n % i == 0L) {
                factors.add(i)
                n /= i
            }
            b++
        }
        if (n > 1) {
            factors.add(n)
        }
        return factors
    }

    fun attack(cipherToAttack: String, N: Long, e: Long) {

        val factorsOfN = factorizeN(N)
        println("Factors of N: ")
        factorsOfN.forEach { print("$it ") }
        println()
        val numberOfFactors = factorsOfN.size


        factorsOfN.forEachIndexed { index, factor ->
            factorsOfN.subList(index + 1, numberOfFactors).forEach {
                val phi = phi(factor, it)
                val inverseOfE = gcdExtended(e, phi).second
                println("Private key: $inverseOfE")

                val originalMessage = decrypt(BigInteger(N.toString()), BigInteger(inverseOfE.toString()), cipherToAttack)
                println("Decrypted message: $originalMessage")
            }
        }
    }
}