<?php

declare(strict_types=1);

namespace CryptoFramework\Adapters;

use CryptoFramework\Exceptions\CryptoException;

/**
 * Interface para adapters de frameworks
 */
interface FrameworkAdapterInterface
{
    /**
     * Criptografa dados usando o mecanismo do framework
     *
     * @param string $data Dados a serem criptografados
     * @param array<string, mixed> $options Opções adicionais
     * @return string Dados criptografados
     * @throws CryptoException
     */
    public function encrypt(string $data, array $options = []): string;
    
    /**
     * Descriptografa dados usando o mecanismo do framework
     *
     * @param string $encryptedData Dados criptografados
     * @param array<string, mixed> $options Opções adicionais
     * @return string Dados descriptografados
     * @throws CryptoException
     */
    public function decrypt(string $encryptedData, array $options = []): string;
    
    /**
     * Cria um hash usando o mecanismo do framework
     *
     * @param string $data Dados a serem hasheados
     * @param array<string, mixed> $options Opções adicionais
     * @return string Hash
     * @throws CryptoException
     */
    public function hash(string $data, array $options = []): string;
    
    /**
     * Verifica um hash usando o mecanismo do framework
     *
     * @param string $data Dados a serem verificados
     * @param string $hash Hash para comparação
     * @return bool True se o hash for válido
     * @throws CryptoException
     */
    public function verifyHash(string $data, string $hash): bool;
    
    /**
     * Retorna o nome do framework
     *
     * @return string Nome do framework
     */
    public function getFrameworkName(): string;
}
