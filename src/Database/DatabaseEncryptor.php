<?php

declare(strict_types=1);

namespace CryptoFramework\Database;

use CryptoFramework\Exceptions\CryptoException;
use CryptoFramework\Interfaces\SymmetricCryptoInterface;
use CryptoFramework\Symmetric\AES256GCM;
use CryptoFramework\Utils\RandomGenerator;

/**
 * Classe para criptografia de dados em banco de dados
 */
final class DatabaseEncryptor
{
    /**
     * @param SymmetricCryptoInterface $cipher Cifra para criptografia
     * @param RandomGenerator $randomGenerator Gerador de números aleatórios
     */
    public function __construct(
        private readonly SymmetricCryptoInterface $cipher = new AES256GCM(),
        private readonly RandomGenerator $randomGenerator = new RandomGenerator()
    ) {
    }
    
    /**
     * Criptografa um valor para armazenamento em banco de dados
     *
     * @param mixed $value Valor a ser criptografado
     * @param string $key Chave de criptografia
     * @param string|null $context Contexto para autenticação adicional
     * @return string Valor criptografado (formato: base64)
     * @throws CryptoException
     */
    public function encryptValue(mixed $value, string $key, ?string $context = null): string
    {
        try {
            // Serializar o valor
            $serialized = serialize($value);
            
            // Criptografar o valor serializado
            return $this->cipher->encrypt($serialized, $key, $context);
        } catch (\Exception $e) {
            throw new CryptoException("Erro ao criptografar valor: " . $e->getMessage(), previous: $e);
        }
    }
    
    /**
     * Descriptografa um valor armazenado em banco de dados
     *
     * @param string $encryptedValue Valor criptografado
     * @param string $key Chave de criptografia
     * @param string|null $context Contexto para autenticação adicional
     * @return mixed Valor descriptografado
     * @throws CryptoException
     */
    public function decryptValue(string $encryptedValue, string $key, ?string $context = null): mixed
    {
        try {
            // Descriptografar o valor
            $serialized = $this->cipher->decrypt($encryptedValue, $key, $context);
            
            // Desserializar o valor
            $value = unserialize($serialized);
            
            if ($value === false && $serialized !== 'b:0;') {
                throw new CryptoException("Falha ao desserializar valor");
            }
            
            return $value;
        } catch (\Exception $e) {
            throw new CryptoException("Erro ao descriptografar valor: " . $e->getMessage(), previous: $e);
        }
    }
    
    /**
     * Criptografa um array de valores para armazenamento em banco de dados
     *
     * @param array<string, mixed> $values Array de valores a serem criptografados
     * @param string $key Chave de criptografia
     * @param array<string> $encryptFields Campos a serem criptografados
     * @param string|null $context Contexto para autenticação adicional
     * @return array<string, mixed> Array com valores criptografados
     * @throws CryptoException
     */
    public function encryptArray(array $values, string $key, array $encryptFields, ?string $context = null): array
    {
        $result = $values;
        
        foreach ($encryptFields as $field) {
            if (isset($values[$field])) {
                $result[$field] = $this->encryptValue($values[$field], $key, $context);
            }
        }
        
        return $result;
    }
    
    /**
     * Descriptografa um array de valores armazenados em banco de dados
     *
     * @param array<string, mixed> $values Array de valores criptografados
     * @param string $key Chave de criptografia
     * @param array<string> $encryptFields Campos criptografados
     * @param string|null $context Contexto para autenticação adicional
     * @return array<string, mixed> Array com valores descriptografados
     * @throws CryptoException
     */
    public function decryptArray(array $values, string $key, array $encryptFields, ?string $context = null): array
    {
        $result = $values;
        
        foreach ($encryptFields as $field) {
            if (isset($values[$field]) && is_string($values[$field])) {
                $result[$field] = $this->decryptValue($values[$field], $key, $context);
            }
        }
        
        return $result;
    }
    
    /**
     * Gera uma chave de criptografia para um modelo específico
     *
     * @param string $modelName Nome do modelo
     * @param string $masterKey Chave mestra
     * @return string Chave de criptografia
     * @throws CryptoException
     */
    public function generateModelKey(string $modelName, string $masterKey): string
    {
        try {
            return hash_hmac('sha256', $modelName, $masterKey, true);
        } catch (\Exception $e) {
            throw new CryptoException("Erro ao gerar chave para modelo: " . $e->getMessage(), previous: $e);
        }
    }
}
