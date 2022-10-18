package com.example.authmre

import android.os.Build
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.example.authmre.ui.theme.AuthmreTheme
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import java.security.Key
import java.security.KeyStore
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

class MainActivity : FragmentActivity() {
    private val keyStore = KeyStore.getInstance("AndroidKeyStore")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            AuthmreTheme {
                MainScreen(
                    onEncryptClick = {
                        try {
                            encrypt(it.encodeToByteArray()).toHexString()
                        } catch (e: Exception) {
                            Toast.makeText(this, "Error: ${e.message ?: "unknown"}", Toast.LENGTH_LONG).show()
                            e.printStackTrace()
                            ""
                        }
                    }
                )
            }
        }

        keyStore.load(null)
    }

    private suspend fun encrypt(message: ByteArray, attemptNo: Int = 1): ByteArray =
        try {
            val key = getMasterKey("__authmre_masterkey__")
            val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding").apply { init(Cipher.ENCRYPT_MODE, key) }

            cipher.doFinal(message)
        } catch (e: UserNotAuthenticatedException) {
            if (attemptNo > 10) throw IllegalStateException("Max authentication attempts exceeded.")
            if (!authenticate()) throw IllegalStateException("Authentication failed.")

            encrypt(message, attemptNo + 1)
        }

    private fun getMasterKey(alias: String): Key {
        if (!keyStore.containsAlias(alias)) {
            generateKey(alias)
        }

        return keyStore.getKey(alias, null)
    }

    private fun generateKey(alias: String) {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT).apply {
            setDigests(KeyProperties.DIGEST_SHA512)
            setUserAuthenticationRequired(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) setUserAuthenticationParameters(5, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
            else setUserAuthenticationValidityDurationSeconds(5)
            setRandomizedEncryptionRequired(true)
            setBlockModes(KeyProperties.BLOCK_MODE_CBC)
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
        }.build()

        val kpg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply { init(spec) }
        kpg.generateKey()
    }

    private suspend fun authenticate(): Boolean {
        val biometricPromptInfo = BiometricPrompt.PromptInfo.Builder().apply {
            setTitle("Authentication")
            setAllowedAuthenticators(BiometricManager.Authenticators.DEVICE_CREDENTIAL or BiometricManager.Authenticators.BIOMETRIC_WEAK)
        }.build()

        val authenticatedDeferred = CompletableDeferred<Boolean>()
        val biometricPrompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this), object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                authenticatedDeferred.complete(false)
            }

            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                authenticatedDeferred.complete(true)
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                authenticatedDeferred.complete(false)
            }
        })

        biometricPrompt.authenticate(biometricPromptInfo)

        return authenticatedDeferred.await()
    }

    private fun ByteArray.toHexString(): String = joinToString("") { "%02x".format(it) }
}

@Composable
fun MainScreen(onEncryptClick: suspend (String) -> String) {
    val coroutineScope = rememberCoroutineScope()

    Surface(
        modifier = Modifier.fillMaxSize(),
        color = MaterialTheme.colors.background,
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            var message by remember { mutableStateOf(UUID.randomUUID().toString()) }
            var encrypted by remember { mutableStateOf("") }

            OutlinedTextField(
                value = message,
                onValueChange = { message = it },
                label = {
                    Text(text = "Message")
                },
            )

            Button(
                onClick = {
                    coroutineScope.launch {
                        encrypted = onEncryptClick(message)
                    }
                },
            ) {
                Text(text = "Encrypt")
            }

            if (encrypted.isNotBlank()) {
                Text(text = encrypted)
            }
        }
    }
}

@Preview(showBackground = true)
@Composable
fun DefaultPreview() {
    AuthmreTheme {
        MainScreen(
            onEncryptClick = { "" }
        )
    }
}