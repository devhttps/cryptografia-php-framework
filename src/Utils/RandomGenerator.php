<?php

declare(strict_types=1);

namespace CryptoFramework\Utils;

use CryptoFramework\Exceptions\CryptoException;

/**
 * Classe para geração de números aleatórios seguros
 */
final class RandomGenerator
{
    /**
     * Gera bytes aleatórios seguros
     *
     * @param int $length Número de bytes a serem gerados
     * @return string Bytes aleatórios
     * @throws CryptoException
     */
    public function generateBytes(int $length): string
    {
        if ($length <= 0) {
            throw new CryptoException("O comprimento deve ser maior que zero");
        }
        
        try {
            return random_bytes($length);
        } catch (\Exception $e) {
            throw new CryptoException("Falha ao gerar bytes aleatórios: " . $e->getMessage(), previous: $e);
        }
    }
    
    /**
     * Gera um número inteiro aleatório seguro
     *
     * @param int $min Valor mínimo (inclusive)
     * @param int $max Valor máximo (inclusive)
     * @return int Número inteiro aleatório
     * @throws CryptoException
     */
    public function generateInt(int $min, int $max): int
    {
        if ($min >= $max) {
            throw new CryptoException("O valor mínimo deve ser menor que o valor máximo");
        }
        
        try {
            return random_int($min, $max);
        } catch (\Exception $e) {
            throw new CryptoException("Falha ao gerar número inteiro aleatório: " . $e->getMessage(), previous: $e);
        }
    }
    
    /**
     * Gera uma string aleatória segura
     *
     * @param int $length Comprimento da string
     * @param string $charset Conjunto de caracteres a serem usados
     * @return string String aleatória
     * @throws CryptoException
     */
    public function generateString(int $length, string $charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'): string
    {
        if ($length <= 0) {
            throw new CryptoException("O comprimento deve ser maior que zero");
        }
        
        if (empty($charset)) {
            throw new CryptoException("O conjunto de caracteres não pode estar vazio");
        }
        
        $charsetLength = strlen($charset);
        $result = '';
        
        try {
            for ($i = 0; $i < $length; $i++) {
                $result .= $charset[$this->generateInt(0, $charsetLength - 1)];
            }
            
            return $result;
        } catch (\Exception $e) {
            throw new CryptoException("Falha ao gerar string aleatória: " . $e->getMessage(), previous: $e);
        }
    }
    
    /**
     * Gera um UUID v4 aleatório
     *
     * @return string UUID v4
     * @throws CryptoException
     */
    public function generateUUID(): string
    {
        try {
            $data = $this->generateBytes(16);
            
            // Definir a versão para 4 (aleatório)
            $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
            // Definir bits IETF variant
            $data[8] = chr(ord($data[8]) & 0x3f | 0x80);
            
            return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
        } catch (\Exception $e) {
            throw new CryptoException("Falha ao gerar UUID: " . $e->getMessage(), previous: $e);
        }
    }
}
