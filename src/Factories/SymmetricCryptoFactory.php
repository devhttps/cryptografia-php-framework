<?php

declare(strict_types=1);

namespace CryptoFramework\Factories;

use CryptoFramework\Exceptions\CryptoException;
use CryptoFramework\Interfaces\SymmetricCryptoInterface;
use CryptoFramework\Symmetric\AES256GCM;
use CryptoFramework\Symmetric\AES256CBC;
use CryptoFramework\Symmetric\ChaCha20Poly1305;
use CryptoFramework\Symmetric\Camellia256GCM;
use CryptoFramework\Utils\RandomGenerator;

/**
 * Fábrica para criar instâncias de criptografia simétrica
 */
final class SymmetricCryptoFactory
{
    /**
     * @param RandomGenerator|null $randomGenerator Gerador de números aleatórios
     */
    public function __construct(
        private readonly ?RandomGenerator $randomGenerator = null
    ) {
    }
    
    /**
     * Cria uma instância de criptografia simétrica
     *
     * @param string $algorithm Algoritmo de criptografia
     * @return SymmetricCryptoInterface Instância de criptografia simétrica
     * @throws CryptoException
     */
    public function create(string $algorithm): SymmetricCryptoInterface
    {
        $randomGenerator = $this->randomGenerator ?? new RandomGenerator();
        
        return match (strtolower($algorithm)) {
            'aes-256-gcm', 'aes256gcm', 'aesgcm' => new AES256GCM($randomGenerator),
            'aes-256-cbc', 'aes256cbc', 'aescbc' => new AES256CBC($randomGenerator),
            'chacha20-poly1305', 'chacha20poly1305', 'chacha20' => new ChaCha20Poly1305($randomGenerator),
            'camellia-256-gcm', 'camellia256gcm', 'camelliagcm' => new Camellia256GCM($randomGenerator),
            default => throw new CryptoException("Algoritmo de criptografia simétrica não suportado: $algorithm"),
        };
    }
    
    /**
     * Retorna os algoritmos de criptografia simétrica disponíveis
     *
     * @return array<string> Lista de algoritmos disponíveis
     */
    public function getAvailableAlgorithms(): array
    {
        $algorithms = [];
        
        if (AES256GCM::isAvailable()) {
            $algorithms[] = 'aes-256-gcm';
        }
        
        if (AES256CBC::isAvailable()) {
            $algorithms[] = 'aes-256-cbc';
        }
        
        if (ChaCha20Poly1305::isAvailable()) {
            $algorithms[] = 'chacha20-poly1305';
        }
        
        if (Camellia256GCM::isAvailable()) {
            $algorithms[] = 'camellia-256-gcm';
        }
        
        return $algorithms;
    }
    
    /**
     * Retorna o algoritmo recomendado
     *
     * @return string Algoritmo recomendado
     * @throws CryptoException
     */
    public function getRecommendedAlgorithm(): string
    {
        $algorithms = $this->getAvailableAlgorithms();
        
        if (in_array('aes-256-gcm', $algorithms, true)) {
            return 'aes-256-gcm';
        }
        
        if (in_array('chacha20-poly1305', $algorithms, true)) {
            return 'chacha20-poly1305';
        }
        
        if (in_array('camellia-256-gcm', $algorithms, true)) {
            return 'camellia-256-gcm';
        }
        
        if (in_array('aes-256-cbc', $algorithms, true)) {
            return 'aes-256-cbc';
        }
        
        throw new CryptoException("Nenhum algoritmo de criptografia simétrica disponível");
    }
}
