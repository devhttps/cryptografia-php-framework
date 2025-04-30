<?php

declare(strict_types=1);

namespace CryptoFramework\Session;

use CryptoFramework\Exceptions\CryptoException;
use CryptoFramework\Interfaces\SymmetricCryptoInterface;
use CryptoFramework\Symmetric\AES256GCM;
use CryptoFramework\Utils\RandomGenerator;
use SessionHandlerInterface;

/**
 * Manipulador de sessão seguro com criptografia
 */
final class SecureSessionHandler implements SessionHandlerInterface
{
    private string $savePath;
    private string $sessionName;
    
    /**
     * @param string $key Chave de criptografia
     * @param SymmetricCryptoInterface $cipher Cifra para criptografia
     * @param RandomGenerator $randomGenerator Gerador de números aleatórios
     */
    public function __construct(
        private readonly string $key,
        private readonly SymmetricCryptoInterface $cipher = new AES256GCM(),
        private readonly RandomGenerator $randomGenerator = new RandomGenerator()
    ) {
        if (strlen($key) < 32) {
            throw new \InvalidArgumentException("A chave de sessão deve ter pelo menos 32 bytes");
        }
    }
    
    /**
     * Inicializa o manipulador de sessão
     *
     * @param string $savePath Caminho para armazenamento das sessões
     * @param string $sessionName Nome da sessão
     * @return bool True se a inicialização for bem-sucedida
     */
    public function open(string $savePath, string $sessionName): bool
    {
        $this->savePath = $savePath;
        $this->sessionName = $sessionName;
        
        if (!is_dir($this->savePath)) {
            if (!mkdir($this->savePath, 0777, true)) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Fecha o manipulador de sessão
     *
     * @return bool True se o fechamento for bem-sucedido
     */
    public function close(): bool
    {
        return true;
    }
    
    /**
     * Lê dados da sessão
     *
     * @param string $id ID da sessão
     * @return string Dados da sessão
     */
    public function read(string $id): string
    {
        $file = $this->getSessionFile($id);
        
        if (!file_exists($file)) {
            return '';
        }
        
        try {
            $encryptedData = file_get_contents($file);
            
            if ($encryptedData === false || empty($encryptedData)) {
                return '';
            }
            
            $data = $this->cipher->decrypt($encryptedData, $this->key, $id);
            return $data;
        } catch (\Exception $e) {
            // Em caso de erro, retornar sessão vazia
            error_log("Erro ao ler sessão: " . $e->getMessage());
            return '';
        }
    }
    
    /**
     * Escreve dados na sessão
     *
     * @param string $id ID da sessão
     * @param string $data Dados da sessão
     * @return bool True se a escrita for bem-sucedida
     */
    public function write(string $id, string $data): bool
    {
        try {
            $file = $this->getSessionFile($id);
            $encryptedData = $this->cipher->encrypt($data, $this->key, $id);
            
            return file_put_contents($file, $encryptedData) !== false;
        } catch (\Exception $e) {
            error_log("Erro ao escrever sessão: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Destrói uma sessão
     *
     * @param string $id ID da sessão
     * @return bool True se a destruição for bem-sucedida
     */
    public function destroy(string $id): bool
    {
        $file = $this->getSessionFile($id);
        
        if (file_exists($file)) {
            return unlink($file);
        }
        
        return true;
    }
    
    /**
     * Coleta de lixo para sessões expiradas
     *
     * @param int $maxlifetime Tempo máximo de vida da sessão
     * @return bool True se a coleta for bem-sucedida
     */
    public function gc(int $maxlifetime): bool
    {
        $pattern = $this->savePath . '/sess_*';
        $files = glob($pattern);
        
        if (!is_array($files)) {
            return false;
        }
        
        $now = time();
        
        foreach ($files as $file) {
            if (filemtime($file) + $maxlifetime < $now && file_exists($file)) {
                unlink($file);
            }
        }
        
        return true;
    }
    
    /**
     * Retorna o caminho para o arquivo de sessão
     *
     * @param string $id ID da sessão
     * @return string Caminho para o arquivo de sessão
     */
    private function getSessionFile(string $id): string
    {
        return $this->savePath . '/sess_' . $id;
    }
    
    /**
     * Configura o manipulador de sessão
     *
     * @param array<string, mixed> $options Opções de configuração
     * @return bool True se a configuração for bem-sucedida
     */
    public static function setup(array $options = []): bool
    {
        // Configurar opções de sessão
        $sessionOptions = [
            'use_strict_mode' => 1,
            'use_cookies' => 1,
            'cookie_httponly' => 1,
            'use_only_cookies' => 1,
            'cookie_secure' => 1,
            'cookie_samesite' => 'Lax',
            'sid_bits_per_character' => 6,
            'sid_length' => 48,
            'cache_limiter' => 'nocache',
            'gc_maxlifetime' => 7200,
        ];
        
        // Mesclar com opções fornecidas
        $sessionOptions = array_merge($sessionOptions, $options);
        
        // Aplicar opções
        foreach ($sessionOptions as $key => $value) {
            ini_set('session.' . $key, (string)$value);
        }
        
        return true;
    }
}
