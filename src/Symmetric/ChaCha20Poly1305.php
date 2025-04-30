<?php

declare(strict_types=1);

namespace CryptoFramework\Symmetric;

use CryptoFramework\Exceptions\CryptoException;
use CryptoFramework\Exceptions\DecryptionException;
use CryptoFramework\Interfaces\SymmetricCryptoInterface;
use CryptoFramework\Utils\RandomGenerator;

/**
 * Implementação de criptografia simétrica usando ChaCha20-Poly1305
 */
final class ChaCha20Poly1305 implements SymmetricCryptoInterface
{
    private const NONCE_LENGTH = 24; // 192 bits para ChaCha20-Poly1305 (libsodium)
    
    public function __construct(
        private readonly RandomGenerator $randomGenerator = new RandomGenerator()
    ) {
        if (!extension_loaded('sodium')) {
            throw new CryptoException("A extensão sodium não está disponível");
        }
    }
    
    /**
     * Criptografa dados usando ChaCha20-Poly1305
     *
     * @param string $data Dados a serem criptografados
     * @param string $key Chave de criptografia (32 bytes)
     * @param string|null $associatedData Dados associados para autenticação adicional
     * @return string Dados criptografados (formato: base64)
     * @throws CryptoException
     */
    public function encrypt(string $data, string $key, ?string $associatedData = null): string
    {
        $this->validateKey($key);

        try {
            // Gerar nonce aleatório
            $nonce = $this->randomGenerator->generateBytes(self::NONCE_LENGTH);
            
            // Criptografar os dados
            $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $data,
                $associatedData ?? '',
                $nonce,
                $key
            );
            
            // Combinar nonce e ciphertext em um único string
            $encrypted = $nonce . $ciphertext;
            
            // Retornar como base64 para facilitar o armazenamento
            return base64_encode($encrypted);
        } catch (\Exception $e) {
            throw new CryptoException("Erro durante a criptografia: " . $e->getMessage(), previous: $e);
        }
    }
    
    /**
     * Descriptografa dados usando ChaCha20-Poly1305
     *
     * @param string $encryptedData Dados criptografados (formato: base64)
     * @param string $key Chave de criptografia (32 bytes)
     * @param string|null $associatedData Dados associados para autenticação adicional
     * @return string Dados descriptografados
     * @throws CryptoException|DecryptionException
     */
    public function decrypt(string $encryptedData, string $key, ?string $associatedData = null): string
    {
        $this->validateKey($key);

        try {
            // Decodificar o base64
            $encrypted = base64_decode($encryptedData, true);
            if ($encrypted === false) {
                throw new DecryptionException("Dados criptografados inválidos: não é um base64 válido");
            }
            
            // Verificar se os dados têm o tamanho mínimo esperado
            if (strlen($encrypted) <= self::NONCE_LENGTH) {
                throw new DecryptionException("Dados criptografados inválidos: tamanho insuficiente");
            }
            
            // Extrair nonce e ciphertext
            $nonce = substr($encrypted, 0, self::NONCE_LENGTH);
            $ciphertext = substr($encrypted, self::NONCE_LENGTH);
            
            // Descriptografar os dados
            $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                $ciphertext,
                $associatedData ?? '',
                $nonce,
                $key
            );
            
            if ($plaintext === false) {
                throw new DecryptionException("Falha na descriptografia: autenticação falhou");
            }
            
            return $plaintext;
        } catch (DecryptionException $e) {
            throw $e;
        } catch (\Exception $e) {
            throw new CryptoException("Erro durante a descriptografia: " . $e->getMessage(), previous: $e);
        }
    }
    
    /**
     * Valida a chave de criptografia
     *
     * @param string $key Chave a ser validada
     * @throws CryptoException
     */
    private function validateKey(string $key): void
    {
        if (strlen($key) !== SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES) {
            throw new CryptoException("A chave ChaCha20-Poly1305 deve ter exatamente " . SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES . " bytes");
        }
    }
    
    /**
     * Verifica se o algoritmo ChaCha20-Poly1305 está disponível
     *
     * @return bool True se o algoritmo estiver disponível
     */
    public static function isAvailable(): bool
    {
        return extension_loaded('sodium');
    }
}
