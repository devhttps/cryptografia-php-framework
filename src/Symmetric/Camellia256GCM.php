<?php

declare(strict_types=1);

namespace CryptoFramework\Symmetric;

use CryptoFramework\Exceptions\CryptoException;
use CryptoFramework\Exceptions\DecryptionException;
use CryptoFramework\Interfaces\SymmetricCryptoInterface;
use CryptoFramework\Utils\RandomGenerator;

/**
 * Implementação de criptografia simétrica usando Camellia-256-GCM
 */
final class Camellia256GCM implements SymmetricCryptoInterface
{
    private const CIPHER_METHOD = 'camellia-256-gcm';
    private const IV_LENGTH = 12; // 96 bits para GCM
    private const TAG_LENGTH = 16; // 128 bits para GCM
    private const KEY_LENGTH = 32; // 256 bits
    
    public function __construct(
        private readonly RandomGenerator $randomGenerator = new RandomGenerator()
    ) {
        if (!in_array(self::CIPHER_METHOD, openssl_get_cipher_methods(), true)) {
            throw new CryptoException("O algoritmo Camellia-256-GCM não está disponível");
        }
    }
    
    /**
     * Criptografa dados usando Camellia-256-GCM
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
            // Gerar IV aleatório
            $iv = $this->randomGenerator->generateBytes(self::IV_LENGTH);
            
            // Variável para armazenar a tag de autenticação
            $tag = '';
            
            // Criptografar os dados
            $ciphertext = openssl_encrypt(
                $data,
                self::CIPHER_METHOD,
                $key,
                OPENSSL_RAW_DATA,
                $iv,
                $tag,
                $associatedData ?? '',
                self::TAG_LENGTH
            );
            
            if ($ciphertext === false) {
                throw new CryptoException("Falha na criptografia: " . openssl_error_string());
            }
            
            // Combinar IV, ciphertext e tag em um único string
            $encrypted = $iv . $ciphertext . $tag;
            
            // Retornar como base64 para facilitar o armazenamento
            return base64_encode($encrypted);
        } catch (\Exception $e) {
            throw new CryptoException("Erro durante a criptografia: " . $e->getMessage(), previous: $e);
        }
    }
    
    /**
     * Descriptografa dados usando Camellia-256-GCM
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
            $minLength = self::IV_LENGTH + self::TAG_LENGTH;
            if (strlen($encrypted) <= $minLength) {
                throw new DecryptionException("Dados criptografados inválidos: tamanho insuficiente");
            }
            
            // Extrair IV, ciphertext e tag
            $iv = substr($encrypted, 0, self::IV_LENGTH);
            $tag = substr($encrypted, -self::TAG_LENGTH);
            $ciphertext = substr($encrypted, self::IV_LENGTH, -self::TAG_LENGTH);
            
            // Descriptografar os dados
            $plaintext = openssl_decrypt(
                $ciphertext,
                self::CIPHER_METHOD,
                $key,
                OPENSSL_RAW_DATA,
                $iv,
                $tag,
                $associatedData ?? ''
            );
            
            if ($plaintext === false) {
                throw new DecryptionException("Falha na descriptografia: " . openssl_error_string());
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
        if (strlen($key) !== self::KEY_LENGTH) {
            throw new CryptoException("A chave Camellia-256 deve ter exatamente " . self::KEY_LENGTH . " bytes");
        }
    }
    
    /**
     * Verifica se o algoritmo Camellia-256-GCM está disponível
     *
     * @return bool True se o algoritmo estiver disponível
     */
    public static function isAvailable(): bool
    {
        return in_array(self::CIPHER_METHOD, openssl_get_cipher_methods(), true);
    }
}
