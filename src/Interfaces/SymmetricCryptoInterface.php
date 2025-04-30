<?php

namespace CryptoFramework\Interfaces;

use CryptoFramework\Exceptions\CryptoException;
use CryptoFramework\Exceptions\DecryptionException;

/**
 * Interface para implementações de criptografia simétrica
 */
interface SymmetricCryptoInterface
{
    /**
     * Criptografa dados
     *
     * @param string $data Dados a serem criptografados
     * @param string $key Chave de criptografia
     * @param string|null $associatedData Dados associados para autenticação adicional
     * @return string Dados criptografados
     * @throws CryptoException
     */
    public function encrypt(string $data, string $key, ?string $associatedData = null): string;
    
    /**
     * Descriptografa dados
     *
     * @param string $encryptedData Dados criptografados
     * @param string $key Chave de criptografia
     * @param string|null $associatedData Dados associados para autenticação adicional
     * @return string Dados descriptografados
     * @throws CryptoException|DecryptionException
     */
    public function decrypt(string $encryptedData, string $key, ?string $associatedData = null): string;
}
