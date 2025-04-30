<?php

namespace CryptoFramework\KeyManagement;

use CryptoFramework\Exceptions\CryptoException;

/**
 * Classe para derivação e gerenciamento de chaves
 */
class KeyDeriver
{
    /**
     * Deriva uma chave a partir de uma senha usando PBKDF2
     *
     * @param string $password Senha
     * @param string $salt Salt
     * @param int $keyLength Tamanho da chave em bytes
     * @param int $iterations Número de iterações
     * @param string $algorithm Algoritmo de hash
     * @return string Chave derivada
     * @throws CryptoException
     */
    public function deriveFromPassword(
        string $password,
        string $salt,
        int $keyLength = 32,
        int $iterations = 100000,
        string $algorithm = 'sha256'
    ): string {
        try {
            if (empty($password)) {
                throw new CryptoException("A senha não pode estar vazia");
            }
            
            if (strlen($salt) < 16) {
                throw new CryptoException("O salt deve ter pelo menos 16 bytes");
            }
            
            if ($iterations < 10000) {
                throw new CryptoException("O número de iterações deve ser pelo menos 10000");
            }
            
            $key = hash_pbkdf2(
                $algorithm,
                $password,
                $salt,
                $iterations,
                $keyLength * 2, // Saída em hexadecimal, então multiplicamos por 2
                true // Saída binária
            );
            
            if ($key === false) {
                throw new CryptoException("Falha ao derivar chave com PBKDF2");
            }
            
            return $key;
        } catch (\Exception $e) {
            throw new CryptoException("Erro durante a derivação de chave PBKDF2: " . $e->getMessage());
        }
    }
    
    /**
     * Expande uma chave mestra usando HKDF
     *
     * @param string $masterKey Chave mestra
     * @param string $info Informação de contexto
     * @param string $salt Salt
     * @param int $keyLength Tamanho da chave em bytes
     * @param string $algorithm Algoritmo de hash
     * @return string Chave expandida
     * @throws CryptoException
     */
    public function expandKey(
        string $masterKey,
        string $info,
        string $salt,
        int $keyLength = 32,
        string $algorithm = 'sha256'
    ): string {
        try {
            if (empty($masterKey)) {
                throw new CryptoException("A chave mestra não pode estar vazia");
            }
            
            $key = hash_hkdf(
                $algorithm,
                $masterKey,
                $keyLength,
                $info,
                $salt
            );
            
            if ($key === false) {
                throw new CryptoException("Falha ao expandir chave com HKDF");
            }
            
            return $key;
        } catch (\Exception $e) {
            throw new CryptoException("Erro durante a expansão de chave HKDF: " . $e->getMessage());
        }
    }
    
    /**
     * Gera um salt aleatório
     *
     * @param int $length Tamanho do salt em bytes
     * @return string Salt gerado
     * @throws CryptoException
     */
    public function generateSalt(int $length = 16): string
    {
        try {
            return random_bytes($length);
        } catch (\Exception $e) {
            throw new CryptoException("Falha ao gerar salt: " . $e->getMessage());
        }
    }
    
    /**
     * Gera uma chave aleatória
     *
     * @param int $length Tamanho da chave em bytes
     * @return string Chave gerada
     * @throws CryptoException
     */
    public function generateKey(int $length = 32): string
    {
        try {
            return random_bytes($length);
        } catch (\Exception $e) {
            throw new CryptoException("Falha ao gerar chave: " . $e->getMessage());
        }
    }
}
