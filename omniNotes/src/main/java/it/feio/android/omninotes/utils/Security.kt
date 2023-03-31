/*
 * Copyright (C) 2013-2022 Federico Iosue (federico@iosue.it)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package it.feio.android.omninotes.utils

import android.util.Base64
import it.feio.android.omninotes.helpers.LogDelegate
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import javax.crypto.*
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class Security private constructor(){

    companion object {
        private const val KEY_SIZE = 128
        private const val ITERATIONS = 10000
        private const val SALT_SIZE = KEY_SIZE / 8
        private const val IV_SIZE = 12 // AES-GCM IV size is 12 bytes
        private const val AUTH_TAG_SIZE = 16 // AES-GCM authentication tag size is 16 bytes

        @JvmStatic
        fun md5(s: String): String {
            return try {
                val digest = MessageDigest.getInstance("MD5")
                digest.update(s.toByteArray())
                val messageDigest = digest.digest()

                // Creates Hex String
                val hexString = StringBuilder()
                for (b in messageDigest) {
                    hexString.append(Integer.toHexString(0xFF and b.toInt()))
                }
                hexString.toString()
            } catch (e: NoSuchAlgorithmException) {
                LogDelegate.w("Something is gone wrong calculating MD5", e)
                ""
            }
        }

        @JvmStatic
        fun encrypt(value: String, password: String): String? {
            return try {
                val salt = ByteArray(SALT_SIZE)
                val random = SecureRandom()
                random.nextBytes(salt)

                val keySpec = PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_SIZE)
                val secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                val keyBytes = secretKeyFactory.generateSecret(keySpec).encoded
                val key = SecretKeySpec(keyBytes, "AES")

                val iv = ByteArray(IV_SIZE)
                random.nextBytes(iv)
                val ivSpec = GCMParameterSpec(AUTH_TAG_SIZE * 8, iv)

                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
                val encrypted = cipher.doFinal(value.toByteArray(StandardCharsets.UTF_8))

                val output = ByteArray(SALT_SIZE + IV_SIZE + encrypted.size)
                System.arraycopy(salt, 0, output, 0, SALT_SIZE)
                System.arraycopy(iv, 0, output, SALT_SIZE, IV_SIZE)
                System.arraycopy(encrypted, 0, output, SALT_SIZE + IV_SIZE, encrypted.size)

                Base64.encodeToString(output, Base64.DEFAULT)
            } catch (e: Exception) {
                LogDelegate.e("Something is gone wrong encrypting", e)
                value
            }
        }

        @JvmStatic
        fun decrypt(encryptedValue: String, password: String): String? {
            return try {
                val decoded = Base64.decode(encryptedValue, Base64.DEFAULT)

                val salt = ByteArray(SALT_SIZE)
                System.arraycopy(decoded, 0, salt, 0, SALT_SIZE)

                val iv = ByteArray(IV_SIZE)
                System.arraycopy(decoded, SALT_SIZE, iv, 0, IV_SIZE)
                val ivSpec = GCMParameterSpec(AUTH_TAG_SIZE * 8, iv)

                val cipherText = ByteArray(decoded.size - SALT_SIZE - IV_SIZE)
                System.arraycopy(decoded, SALT_SIZE + IV_SIZE, cipherText, 0, cipherText.size)

                val keySpec = PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_SIZE)
                val secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                val keyBytes = secretKeyFactory.generateSecret(keySpec).encoded
                val key = SecretKeySpec(keyBytes, "AES")

                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, key, ivSpec)
                val decrypted = cipher.doFinal(cipherText)

                String(decrypted, StandardCharsets.UTF_8)
            } catch (e: Exception) {
                LogDelegate.e("Something is gone wrong decrypting", e)
                null
            }
        }

    }
}