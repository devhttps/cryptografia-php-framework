<?php

namespace CryptoFramework\Asymmetric;

use CryptoFramework\Exceptions\CryptoException;
use CryptoFramework\Interfaces\AsymmetricCryptoInterface;

/**
 * Implementação de criptografia assimétrica usando ECC (Elliptic Curve Cryptography)
 */
class ECCCrypto implements AsymmetricCryptoInterface
{
    private const DEFAULT_CURVE = 'secp384r1'; // Curva P-384
    private const DEFAULT_DIGEST_ALGORITHM = 'sha384';
    
    /**
     * Gera um par de chaves ECC
     *
     * @param string $curve Nome da curva elíptica
     * @return array Array contendo as chaves pública e privada
     * @throws CryptoException
     */
    public function generateKeyPair(string $curve = self::DEFAULT_CURVE): array
    {
        try {
            // Configurar opções para geração de chave
            $config = [
                'private_key_type' => OPENSSL_KEYTYPE_EC,
                'curve_name' => $curve
            ];
            
            // Gerar o par de chaves
            $resource = openssl_pkey_new($config);
            if ($resource === false) {
                throw new CryptoException("Falha ao gerar par de chaves ECC: " . openssl_error_string());
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
            throw new CryptoException("Erro ao gerar par de chaves ECC: " . $e->getMessage());
        }
    }
    
    /**
     * Assina dados usando ECC
     *
     * @param string $privateKey Chave privada ECC
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
                throw new CryptoException("Chave privada ECC inválida: " . openssl_error_string());
            }
            
            // Assinar os dados
            $signature = '';
            $result = openssl_sign($data, $signature, $privateKeyResource, $digestAlgorithm);
            
            if ($result === false) {
                throw new CryptoException("Falha ao assinar dados com ECC: " . openssl_error_string());
            }
            
            // Liberar recursos
            openssl_free_key($privateKeyResource);
            
            // Retornar como base64
            return base64_encode($signature);
        } catch (\Exception $e) {
            throw new CryptoException("Erro durante a assinatura ECC: " . $e->getMessage());
        }
    }
    
    /**
     * Verifica a assinatura de dados usando ECC
     *
     * @param string $publicKey Chave pública ECC
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
                throw new CryptoException("Chave pública ECC inválida: " . openssl_error_string());
            }
            
            // Verificar a assinatura
            $result = openssl_verify($data, $binarySignature, $publicKeyResource, $digestAlgorithm);
            
            // Liberar recursos
            openssl_free_key($publicKeyResource);
            
            if ($result === -1) {
                throw new CryptoException("Erro ao verificar assinatura ECC: " . openssl_error_string());
            }
            
            return $result === 1;
        } catch (\Exception $e) {
            throw new CryptoException("Erro durante a verificação da assinatura ECC: " . $e->getMessage());
        }
    }
    
    /**
     * ECC não suporta criptografia direta como RSA
     * Para criptografia, use ECDH para derivar uma chave compartilhada e depois use criptografia simétrica
     */
    public function encrypt(string $publicKey, string $data): string
    {
        throw new CryptoException("ECC não suporta criptografia direta. Use ECDH para derivar uma chave compartilhada.");
    }
    
    /**
     * ECC não suporta descriptografia direta como RSA
     */
    public function decrypt(string $privateKey, string $encryptedData): string
    {
        throw new CryptoException("ECC não suporta descriptografia direta. Use ECDH para derivar uma chave compartilhada.");
    }
    
    /**
     * Deriva uma chave compartilhada usando ECDH (Elliptic Curve Diffie-Hellman)
     *
     * @param string $privateKey Chave privada local
     * @param string $publicKey Chave pública remota
     * @param int $keyLength Tamanho da chave derivada em bytes
     * @return string Chave compartilhada
     * @throws CryptoException
     */
    public function deriveSharedKey(string $privateKey, string $publicKey, int $keyLength = 32): string
    {
        try {
            // Carregar a chave privada
            $privateKeyResource = openssl_pkey_get_private($privateKey);
            if ($privateKeyResource === false) {
                throw new CryptoException("Chave privada ECC inválida: " . openssl_error_string());
            }
            
            // Carregar a chave pública
            $publicKeyResource = openssl_pkey_get_public($publicKey);
            if ($publicKeyResource === false) {
                throw new CryptoException("Chave pública ECC inválida: " . openssl_error_string());
            }
            
            // Derivar a chave compartilhada
            $sharedSecret = openssl_pkey_derive($publicKeyResource, $privateKeyResource);
            if ($sharedSecret === false) {
                throw new CryptoException("Falha ao derivar chave compartilhada ECDH: " . openssl_error_string());
            }
            
            // Liberar recursos
            openssl_free_key($privateKeyResource);
            openssl_free_key($publicKeyResource);
            
            // Usar HKDF para derivar uma chave de tamanho específico
            $key = hash_hkdf('sha256', $sharedSecret, $keyLength, 'ECDH-Shared-Key');
            
            return $key;
        } catch (\Exception $e) {
            throw new CryptoException("Erro durante a derivação de chave ECDH: " . $e->getMessage());
        }
    }
}
