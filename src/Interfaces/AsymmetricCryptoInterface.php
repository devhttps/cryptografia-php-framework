<?php

namespace CryptoFramework\Interfaces;

use CryptoFramework\Exceptions\CryptoException;

/**
 * Interface para implementações de criptografia assimétrica
 */
interface AsymmetricCryptoInterface
{
    /**
     * Criptografa dados
     *
     * @param string $publicKey Chave pública
     * @param string $data Dados a serem criptografados
     * @return string Dados criptografados
     * @throws CryptoException
     */
    public function encrypt(string $publicKey, string $data): string;
    
    /**
     * Descriptografa dados
     *
     * @param string $privateKey Chave privada
     * @param string $encryptedData Dados criptografados
     * @return string Dados descriptografados
     * @throws CryptoException
     */
    public function decrypt(string $privateKey, string $encryptedData): string;
    
    /**
     * Assina dados
     *
     * @param string $privateKey Chave privada
     * @param string $data Dados a serem assinados
     * @return string Assinatura
     * @throws CryptoException
     */
    public function sign(string $privateKey, string $data): string;
    
    /**
     * Verifica a assinatura de dados
     *
     * @param string $publicKey Chave pública
     * @param string $data Dados assinados
     * @param string $signature Assinatura a ser verificada
     * @return bool True se a assinatura for válida
     * @throws CryptoException
     */
    public function verify(string $publicKey, string $data, string $signature): bool;
}
