<?php

declare(strict_types=1);

namespace CryptoFramework\Hashing;

use CryptoFramework\Exceptions\CryptoException;
use CryptoFramework\Interfaces\HashingInterface;

/**
 * Implementação de hashing seguro para senhas
 */
final class SecureHasher implements HashingInterface
{
    // Configurações padrão para Argon2id
    private const DEFAULT_OPTIONS = [
        'algorithm' => PASSWORD_ARGON2ID,
        'memory_cost' => 65536, // 64MB
        'time_cost' => 4,       // 4 iterações
        'threads' => 1          // 1 thread
    ];
    
    /**
     * Cria um hash seguro para uma senha
     *
     * @param string $password Senha a ser hasheada
     * @param array<string, mixed> $options Opções de configuração para o algoritmo
     * @return string Hash da senha
     * @throws CryptoException
     */
    public function hash(string $password, array $options = []): string
    {
        // Mesclar opções padrão com as fornecidas
        $options = array_merge(self::DEFAULT_OPTIONS, $options);
        
        try {
            $hash = password_hash($password, $options['algorithm'], [
                'memory_cost' => $options['memory_cost'],
                'time_cost' => $options['time_cost'],
                'threads' => $options['threads']
            ]);
            
            if ($hash === false) {
                throw new CryptoException("Falha ao criar hash da senha");
            }
            
            return $hash;
        } catch (\Exception $e) {
            throw new CryptoException("Erro ao criar hash: " . $e->getMessage(), previous: $e);
        }
    }
    
    /**
     * Verifica se uma senha corresponde a um hash
     *
     * @param string $password Senha a ser verificada
     * @param string $hash Hash para comparação
     * @return bool True se a senha corresponder ao hash
     */
    public function verify(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }
    
    /**
     * Verifica se um hash precisa ser atualizado
     *
     * @param string $hash Hash para verificação
     * @param array<string, mixed> $options Opções de configuração para o algoritmo
     * @return bool True se o hash precisar ser atualizado
     */
    public function needsRehash(string $hash, array $options = []): bool
    {
        // Mesclar opções padrão com as fornecidas
        $options = array_merge(self::DEFAULT_OPTIONS, $options);
        
        return password_needs_rehash($hash, $options['algorithm'], [
            'memory_cost' => $options['memory_cost'],
            'time_cost' => $options['time_cost'],
            'threads' => $options['threads']
        ]);
    }
    
    /**
     * Retorna informações sobre um hash
     *
     * @param string $hash Hash para análise
     * @return array<string, mixed>|false Informações sobre o hash ou false em caso de falha
     */
    public function getInfo(string $hash): array|false
    {
        return password_get_info($hash);
    }
    
    /**
     * Verifica se o algoritmo de hashing está disponível
     *
     * @param int $algorithm Algoritmo a ser verificado
     * @return bool True se o algoritmo estiver disponível
     */
    public static function isAlgorithmAvailable(int $algorithm): bool
    {
        return defined('PASSWORD_ARGON2ID') && $algorithm === PASSWORD_ARGON2ID;
    }
    
    /**
     * Retorna o algoritmo recomendado para hashing de senhas
     *
     * @return int Algoritmo recomendado
     */
    public static function getRecommendedAlgorithm(): int
    {
        if (defined('PASSWORD_ARGON2ID')) {
            return PASSWORD_ARGON2ID;
        }
        
        if (defined('PASSWORD_ARGON2I')) {
            return PASSWORD_ARGON2I;
        }
        
        return PASSWORD_BCRYPT;
    }
}
