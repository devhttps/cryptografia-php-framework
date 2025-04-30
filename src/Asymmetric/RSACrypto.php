<?php

namespace CryptoFramework\Asymmetric;

use CryptoFramework\Exceptions\CryptoException;
use CryptoFramework\Interfaces\AsymmetricCryptoInterface;

/**
 * Implementação de criptografia assimétrica usando RSA
 */
class RSACrypto implements AsymmetricCryptoInterface
{
    private const DEFAULT_DIGEST_ALGORITHM = 'sha256';
    
    /**
     * Gera um par de chaves RSA
     *
     * @param int $bits Tamanho da chave em bits
     * @return array Array contendo as chaves pública e privada
     * @throws CryptoException
     */
    public function generateKeyPair(int $bits = 4096): array
    {
        if ($bits < 2048) {
            throw new CryptoException("O tamanho da chave RSA deve ser de pelo menos 2048 bits");
        }
        
        try {
            // Configurar opções para geração de chave
            $config = [
                'private_key_bits' => $bits,
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
            ];
            
            // Gerar o par de chaves
            $resource = openssl_pkey_new($config);
            if ($resource === false) {
                throw new CryptoException("Falha ao gerar par de chaves RSA: " . openssl_error_string());
            }
            
            // Extrair a chave privada
            openssl_pkey_export($resource, $privateKey);
            
            // Extrair a chave pública
            $details = openssl_pkey_get_details($resource);
            $publicKey = $details['key'];
            
            return [
                'private' => $privateKey,
                'public' => $publicKey
            ];
        } catch (\Exception $e) {
            throw new CryptoException("Erro ao gerar par de chaves RSA: " . $e->getMessage());
        }
    }
    
    /**
     * Criptografa dados usando RSA
     *
     * @param string $publicKey Chave pública RSA
     * @param string $data Dados a serem criptografados
     * @return string Dados criptografados (formato: base64)
     * @throws CryptoException
     */
    public function encrypt(string $publicKey, string $data): string
    {
        try {
            // Carregar a chave pública
            $publicKeyResource = openssl_pkey_get_public($publicKey);
            if ($publicKeyResource === false) {
                throw new CryptoException("Chave pública RSA inválida: " . openssl_error_string());
            }
            
            // Criptografar os dados
            $encrypted = '';
            $result = openssl_public_encrypt($data, $encrypted, $publicKeyResource, OPENSSL_PKCS1_OAEP_PADDING);
            
            if ($result === false) {
                throw new CryptoException("Falha ao criptografar dados com RSA: " . openssl_error_string());
            }
            
            // Liberar recursos
            openssl_free_key($publicKeyResource);
            
            // Retornar como base64
            return base64_encode($encrypted);
        } catch (\Exception $e) {
            throw new CryptoException("Erro durante a criptografia RSA: " . $e->getMessage());
        }
    }
    
    /**
     * Descriptografa dados usando RSA
     *
     * @param string $privateKey Chave privada RSA
     * @param string $encryptedData Dados criptografados (formato: base64)
     * @return string Dados descriptografados
     * @throws CryptoException
     */
    public function decrypt(string $privateKey, string $encryptedData): string
    {
        try {
            // Decodificar o base64
            $encrypted = base64_decode($encryptedData, true);
            if ($encrypted === false) {
                throw new CryptoException("Dados criptografados inválidos: não é um base64 válido");
            }
            
            // Carregar a chave privada
            $privateKeyResource = openssl_pkey_get_private($privateKey);
            if ($privateKeyResource === false) {
                throw new CryptoException("Chave privada RSA inválida: " . openssl_error_string());
            }
            
            // Descriptografar os dados
            $decrypted = '';
            $result = openssl_private_decrypt($encrypted, $decrypted, $privateKeyResource, OPENSSL_PKCS1_OAEP_PADDING);
            
            if ($result === false) {
                throw new CryptoException("Falha ao descriptografar dados com RSA: " . openssl_error_string());
            }
            
            // Liberar recursos
            openssl_free_key($privateKeyResource);
            
            return $decrypted;
        } catch (\Exception $e) {
            throw new CryptoException("Erro durante a descriptografia RSA: " . $e->getMessage());
        }
    }
    
    /**
     * Assina dados usando RSA
     *
     * @param string $privateKey Chave privada RSA
     * @param string $data Dados a serem assinados
     * @param string $digestAlgorithm Algoritmo de digest
     * @return string Assinatura (formato: base64)
     * @throws CryptoException
     */
    public function sign(string $privateKey, string $data, string $digestAlgorithm = self::DEFAULT_DIGEST_ALGORITHM): string
    {
        try {
            // Carregar a chave privada
            $privateKeyResource = openssl_pkey_get_private($privateKey);
            if ($privateKeyResource === false) {
                throw new CryptoException("Chave privada RSA inválida: " . openssl_error_string());
            }
            
            // Assinar os dados
            $signature = '';
            $result = openssl_sign($data, $signature, $privateKeyResource, $digestAlgorithm);
            
            if ($result === false) {
                throw new CryptoException("Falha ao assinar dados com RSA: " . openssl_error_string());
            }
            
            // Liberar recursos
            openssl_free_key($privateKeyResource);
            
            // Retornar como base64
            return base64_encode($signature);
        } catch (\Exception $e) {
            throw new CryptoException("Erro durante a assinatura RSA: " . $e->getMessage());
        }
    }
    
    /**
     * Verifica a assinatura de dados usando RSA
     *
     * @param string $publicKey Chave pública RSA
     * @param string $data Dados assinados
     * @param string $signature Assinatura a ser verificada (formato: base64)
     * @param string $digestAlgorithm Algoritmo de digest
     * @return bool True se a assinatura for válida
     * @throws CryptoException
     */
    public function verify(string $publicKey, string $data, string $signature, string $digestAlgorithm = self::DEFAULT_DIGEST_ALGORITHM): bool
    {
        try {
            // Decodificar a assinatura
            $binarySignature = base64_decode($signature, true);
            if ($binarySignature === false) {
                throw new CryptoException("Assinatura inválida: não é um base64 válido");
            }
            
            // Carregar a chave pública
            $publicKeyResource = openssl_pkey_get_public($publicKey);
            if ($publicKeyResource === false) {
                throw new CryptoException("Chave pública RSA inválida: " . openssl_error_string());
            }
            
            // Verificar a assinatura
            $result = openssl_verify($data, $binarySignature, $publicKeyResource, $digestAlgorithm);
            
            // Liberar recursos
            openssl_free_key($publicKeyResource);
            
            if ($result === -1) {
                throw new CryptoException("Erro ao verificar assinatura RSA: " . openssl_error_string());
            }
            
            return $result === 1;
        } catch (\Exception $e) {
            throw new CryptoException("Erro durante a verificação da assinatura RSA: " . $e->getMessage());
        }
    }
}
