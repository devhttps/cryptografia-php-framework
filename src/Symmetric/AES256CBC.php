<?php

declare(strict_types=1);

namespace CryptoFramework\Symmetric;

use CryptoFramework\Exceptions\CryptoException;
use CryptoFramework\Exceptions\DecryptionException;
use CryptoFramework\Interfaces\SymmetricCryptoInterface;
use CryptoFramework\Utils\RandomGenerator;
use CryptoFramework\Utils\ConstantTime;

/**
 * Implementação de criptografia simétrica usando AES-256-CBC
 */
final class AES256CBC implements SymmetricCryptoInterface
{
    private const CIPHER_METHOD = 'aes-256-cbc';
    private const IV_LENGTH = 16; // 128 bits para CBC
    private const KEY_LENGTH = 32; // 256 bits
    private const HMAC_ALGO = 'sha256';
    
    public function __construct(
        private readonly RandomGenerator $randomGenerator = new RandomGenerator(),
        private readonly ConstantTime $constantTime = new ConstantTime()
    ) {
    }
    
    /**
     * Criptografa dados usando AES-256-CBC com HMAC para autenticação
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
            
            // Criptografar os dados
            $ciphertext = openssl_encrypt(
                $data,
                self::CIPHER_METHOD,
                $key,
                OPENSSL_RAW_DATA,
                $iv
            );
            
            if ($ciphertext === false) {
                throw new CryptoException("Falha na criptografia: " . openssl_error_string());
            }
            
            // Calcular HMAC para autenticação
            $hmac = hash_hmac(
                self::HMAC_ALGO,
                $iv . $ciphertext . ($associatedData ?? ''),
                $key,
                true
            );
            
            // Combinar IV, ciphertext e HMAC em um único string
            $encrypted = $iv . $ciphertext . $hmac;
            
            // Retornar como base64 para facilitar o armazenamento
            return base64_encode($encrypted);
        } catch (\Exception $e) {
            throw new CryptoException("Erro durante a criptografia: " . $e->getMessage(), previous: $e);
        }
    }
    
    /**
     * Descriptografa dados usando AES-256-CBC com verificação HMAC
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
            $hmacLength = strlen(hash(self::HMAC_ALGO, '', true));
            $minLength = self::IV_LENGTH + $hmacLength;
            if (strlen($encrypted) <= $minLength) {
                throw new DecryptionException("Dados criptografados inválidos: tamanho insuficiente");
            }
            
            // Extrair IV, ciphertext e HMAC
            $iv = substr($encrypted, 0, self::IV_LENGTH);
            $hmac = substr($encrypted, -$hmacLength);
            $ciphertext = substr($encrypted, self::IV_LENGTH, -$hmacLength);
            
            // Verificar HMAC
            $expectedHmac = hash_hmac(
                self::HMAC_ALGO,
                $iv . $ciphertext . ($associatedData ?? ''),
                $key,
                true
            );
            
            if (!$this->constantTime->compare($expectedHmac, $hmac)) {
                throw new DecryptionException("Falha na descriptografia: HMAC inválido");
            }
            
            // Descriptografar os dados
            $plaintext = openssl_decrypt(
                $ciphertext,
                self::CIPHER_METHOD,
                $key,
                OPENSSL_RAW_DATA,
                $iv
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
            throw new CryptoException("A chave AES-256 deve ter exatamente " . self::KEY_LENGTH . " bytes");
        }
    }
    
    /**
     * Verifica se o algoritmo AES-256-CBC está disponível
     *
     * @return bool True se o algoritmo estiver disponível
     */
    public static function isAvailable(): bool
    {
        return in_array(self::CIPHER_METHOD, openssl_get_cipher_methods(), true);
    }
}
