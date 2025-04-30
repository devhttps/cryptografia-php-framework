<?php

declare(strict_types=1);

namespace CryptoFramework\Adapters;

use CryptoFramework\Exceptions\CryptoException;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Contracts\Hashing\Hasher;

/**
 * Adapter para o framework Laravel
 */
final class LaravelAdapter implements FrameworkAdapterInterface
{
    /**
     * @param Encrypter $encrypter Serviço de criptografia do Laravel
     * @param Hasher $hasher Serviço de hashing do Laravel
     */
    public function __construct(
        private readonly Encrypter $encrypter,
        private readonly Hasher $hasher
    ) {
    }
    
    /**
     * Criptografa dados usando o mecanismo do Laravel
     *
     * @param string $data Dados a serem criptografados
     * @param array<string, mixed> $options Opções adicionais
     * @return string Dados criptografados
     * @throws CryptoException
     */
    public function encrypt(string $data, array $options = []): string
    {
        try {
            return $this->encrypter->encrypt($data, $options['serialize'] ?? true);
        } catch (\Exception $e) {
            throw new CryptoException("Erro ao criptografar dados com Laravel: " . $e->getMessage(), previous: $e);
        }
    }
    
    /**
     * Descriptografa dados usando o mecanismo do Laravel
     *
     * @param string $encryptedData Dados criptografados
     * @param array<string, mixed> $options Opções adicionais
     * @return string Dados descriptografados
     * @throws CryptoException
     */
    public function decrypt(string $encryptedData, array $options = []): string
    {
        try {
            return $this->encrypter->decrypt($encryptedData, $options['unserialize'] ?? true);
        } catch (\Exception $e) {
            throw new CryptoException("Erro ao descriptografar dados com Laravel: " . $e->getMessage(), previous: $e);
        }
    }
    
    /**
     * Cria um hash usando o mecanismo do Laravel
     *
     * @param string $data Dados a serem hasheados
     * @param array<string, mixed> $options Opções adicionais
     * @return string Hash
     * @throws CryptoException
     */
    public function hash(string $data, array $options = []): string
    {
        try {
            return $this->hasher->make($data, $options);
        } catch (\Exception $e) {
            throw new CryptoException("Erro ao criar hash com Laravel: " . $e->getMessage(), previous: $e);
        }
    }
    
    /**
     * Verifica um hash usando o mecanismo do Laravel
     *
     * @param string $data Dados a serem verificados
     * @param string $hash Hash para comparação
     * @return bool True se o hash for válido
     * @throws CryptoException
     */
    public function verifyHash(string $data, string $hash): bool
    {
        try {
            return $this->hasher->check($data, $hash);
        } catch (\Exception $e) {
            throw new CryptoException("Erro ao verificar hash com Laravel: " . $e->getMessage(), previous: $e);
        }
    }
    
    /**
     * Retorna o nome do framework
     *
     * @return string Nome do framework
     */
    public function getFrameworkName(): string
    {
        return 'Laravel';
    }
}
