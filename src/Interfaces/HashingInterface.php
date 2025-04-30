<?php

namespace CryptoFramework\Interfaces;

use CryptoFramework\Exceptions\CryptoException;

/**
 * Interface para implementações de hashing
 */
interface HashingInterface
{
    /**
     * Cria um hash
     *
     * @param string $data Dados a serem hasheados
     * @param array $options Opções de configuração para o algoritmo
     * @return string Hash
     * @throws CryptoException
     */
    public function hash(string $data, array $options = []): string;
    
    /**
     * Verifica se os dados correspondem a um hash
     *
     * @param string $data Dados a serem verificados
     * @param string $hash Hash para comparação
     * @return bool True se os dados corresponderem ao hash
     */
    public function verify(string $data, string $hash): bool;
}
