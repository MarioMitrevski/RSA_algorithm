import java.math.BigInteger

fun main() {
    println("\n--------------------------------------------------------- Encrypt & Decrypt---------------------------------------------------------\n")
    encryptDecryptMessage()
    println("\n--------------------------------------------------------- Attack---------------------------------------------------------\n")
    attackMessage()
}

fun encryptDecryptMessage() {
    val keySize = 2048

    val keys = RSA.generateKeys(
        BigInteger.probablePrime(keySize / 2, java.util.Random()),
        BigInteger.probablePrime(keySize / 2, java.util.Random())
    )

    keys.errorMessage?.let {
        println(it)
        return
    }

    println("Public key\n N: ${keys.publicKey?.first}\n e: ${keys.publicKey?.second}")
    println("Private key\n d: ${keys.privateKey}")

    val messageToBeEncrypted =
        "Crypto currency is a digital or virtual currency that is secured by cryptography, which makes it nearly impossible to counterfeit or double-spend."
    println("Original message: $messageToBeEncrypted")
    val cipherText = RSA.encrypt(
        publicKey = keys.publicKey!!,
        messageToBeEncrypted
    )

    println("Cipher text: $cipherText")
    val originalMessage = RSA.decrypt(keys.publicKey.first, keys.privateKey!!, cipherText)
    println("Decrypted message: $originalMessage")

}

fun attackMessage() {
    val keySize = 32

    val keys = RSA.generateKeys(
        BigInteger.probablePrime(keySize / 2, java.util.Random()),
        BigInteger.probablePrime(keySize / 2, java.util.Random())
    )

    keys.errorMessage?.let {
        println(it)
        return
    }

    println("Public key\n N: ${keys.publicKey?.first}\n e: ${keys.publicKey?.second}")

    val messageToBeEncrypted = "Pivo"
    val cipherText = RSA.encrypt(
        publicKey = keys.publicKey!!,
        messageToBeEncrypted
    )
    println("Cipher text: $cipherText")
    RSA.attack(cipherText, keys.publicKey.first.toLong(), keys.publicKey.second.toLong())

}
