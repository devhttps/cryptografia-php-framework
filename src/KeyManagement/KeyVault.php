<?php

declare(strict_types=1);

namespace CryptoFramework\KeyManagement;

use CryptoFramework\Exceptions\CryptoException;
use CryptoFramework\Symmetric\AES256GCM;
use CryptoFramework\Utils\RandomGenerator;

/**
 * Classe para armazenamento seguro de chaves
 */
final class KeyVault
{
    private string $masterKey;
    private string $storageDirectory;
    private AES256GCM $cipher;
    private RandomGenerator $randomGenerator;
    
    /**
     * @param string $masterKey Chave mestra para criptografar as chaves armazenadas
     * @param string $storageDirectory Diretório para armazenamento das chaves
     * @param AES256GCM|null $cipher Cifra para criptografia das chaves
     * @param RandomGenerator|null $randomGenerator Gerador de números aleatórios
     * @throws CryptoException
     */
    public function __construct(
        string $masterKey,
        string $storageDirectory,
        ?AES256GCM $cipher = null,
        ?RandomGenerator $randomGenerator = null
    ) {
        if (strlen($masterKey) < 32) {
            throw new CryptoException("A chave mestra deve ter pelo menos 32 bytes");
        }
        
        if (!is_dir($storageDirectory) && !mkdir($storageDirectory, 0700, true)) {
            throw new CryptoException("Não foi possível criar o diretório de armazenamento");
        }
        
        $this->masterKey = $masterKey;
        $this->storageDirectory = rtrim($storageDirectory, '/\\') . DIRECTORY_SEPARATOR;
        $this->cipher = $cipher ?? new AES256GCM();
        $this->randomGenerator = $randomGenerator ?? new RandomGenerator();
    }
    
    /**
     * Armazena uma chave no cofre
     *
     * @param string $keyId Identificador da chave
     * @param string $key Chave a ser armazenada
     * @param array<string, mixed> $metadata Metadados da chave
     * @return bool True se a chave foi armazenada com sucesso
     * @throws CryptoException
     */
    public function storeKey(string $keyId, string $key, array $metadata = []): bool
    {
        $this->validateKeyId($keyId);
        
        $keyData = [
            'key' => base64_encode($key),
            'metadata' => $metadata,
            'created' => time(),
            'version' => 1
        ];
        
        $keyJson = json_encode($keyData);
        if ($keyJson === false) {
            throw new CryptoException("Falha ao codificar dados da chave");
        }
        
        $encryptedKey = $this->cipher->encrypt($keyJson, $this->masterKey, $keyId);
        $keyPath = $this->getKeyPath($keyId);
        
        if (file_put_contents($keyPath, $encryptedKey) === false) {
            throw new CryptoException("Falha ao armazenar chave no disco");
        }
        
        return true;
    }
    
    /**
     * Recupera uma chave do cofre
     *
     * @param string $keyId Identificador da chave
     * @return string Chave recuperada
     * @throws CryptoException
     */
    public function retrieveKey(string $keyId): string
    {
        $this->validateKeyId($keyId);
        
        $keyPath = $this->getKeyPath($keyId);
        
        if (!file_exists($keyPath)) {
            throw new CryptoException("Chave não encontrada: " . $keyId);
        }
        
        $encryptedKey = file_get_contents($keyPath);
        if ($encryptedKey === false) {
            throw new CryptoException("Falha ao ler chave do disco");
        }
        
        $keyJson = $this->cipher->decrypt($encryptedKey, $this->masterKey, $keyId);
        $keyData = json_decode($keyJson, true);
        
        if (!is_array($keyData) || !isset($keyData['key'])) {
            throw new CryptoException("Dados da chave inválidos");
        }
        
        $key = base64_decode($keyData['key'], true);
        if ($key === false) {
            throw new CryptoException("Falha ao decodificar chave");
        }
        
        return $key;
    }
    
    /**
     * Rotaciona uma chave no cofre
     *
     * @param string $keyId Identificador da chave
     * @param string $newKey Nova chave
     * @return bool True se a chave foi rotacionada com sucesso
     * @throws CryptoException
     */
    public function rotateKey(string $keyId, string $newKey): bool
    {
        $this->validateKeyId($keyId);
        
        $keyPath = $this->getKeyPath($keyId);
        
        if (!file_exists($keyPath)) {
            throw new CryptoException("Chave não encontrada: " . $keyId);
        }
        
        // Recuperar metadados da chave atual
        $encryptedKey = file_get_contents($keyPath);
        if ($encryptedKey === false) {
            throw new CryptoException("Falha ao ler chave do disco");
        }
        
        $keyJson = $this->cipher->decrypt($encryptedKey, $this->masterKey, $keyId);
        $keyData = json_decode($keyJson, true);
        
        if (!is_array($keyData) || !isset($keyData['metadata'])) {
            throw new CryptoException("Dados da chave inválidos");
        }
        
        // Armazenar a chave antiga no histórico
        $historyPath = $this->getKeyHistoryPath($keyId, $keyData['version'] ?? 1);
        if (file_put_contents($historyPath, $encryptedKey) === false) {
            throw new CryptoException("Falha ao armazenar histórico da chave");
        }
        
        // Atualizar a versão e armazenar a nova chave
        $keyData['key'] = base64_encode($newKey);
        $keyData['updated'] = time();
        $keyData['version'] = ($keyData['version'] ?? 1) + 1;
        
        $newKeyJson = json_encode($keyData);
        if ($newKeyJson === false) {
            throw new CryptoException("Falha ao codificar dados da nova chave");
        }
        
        $newEncryptedKey = $this->cipher->encrypt($newKeyJson, $this->masterKey, $keyId);
        
        if (file_put_contents($keyPath, $newEncryptedKey) === false) {
            throw new CryptoException("Falha ao armazenar nova chave no disco");
        }
        
        return true;
    }
    
    /**
     * Exclui uma chave do cofre
     *
     * @param string $keyId Identificador da chave
     * @return bool True se a chave foi excluída com sucesso
     * @throws CryptoException
     */
    public function deleteKey(string $keyId): bool
    {
        $this->validateKeyId($keyId);
        
        $keyPath = $this->getKeyPath($keyId);
        
        if (!file_exists($keyPath)) {
            throw new CryptoException("Chave não encontrada: " . $keyId);
        }
        
        if (!unlink($keyPath)) {
            throw new CryptoException("Falha ao excluir chave do disco");
        }
        
        // Excluir histórico da chave
        $historyPattern = $this->storageDirectory . $keyId . '.*.key';
        $historyFiles = glob($historyPattern);
        
        if (is_array($historyFiles)) {
            foreach ($historyFiles as $historyFile) {
                unlink($historyFile);
            }
        }
        
        return true;
    }
    
    /**
     * Lista todas as chaves no cofre
     *
     * @return array<string> Lista de identificadores de chaves
     */
    public function listKeys(): array
    {
        $pattern = $this->storageDirectory . '*.key';
        $keyFiles = glob($pattern);
        
        if (!is_array($keyFiles)) {
            return [];
        }
        
        $keys = [];
        foreach ($keyFiles as $keyFile) {
            $keyId = basename($keyFile, '.key');
            if (strpos($keyId, '.') === false) {
                $keys[] = $keyId;
            }
        }
        
        return $keys;
    }
    
    /**
     * Valida um identificador de chave
     *
     * @param string $keyId Identificador da chave
     * @throws CryptoException
     */
    private function validateKeyId(string $keyId): void
    {
        if (empty($keyId) || !preg_match('/^[a-zA-Z0-9_-]+$/', $keyId)) {
            throw new CryptoException("Identificador de chave inválido");
        }
    }
    
    /**
     * Retorna o caminho para uma chave
     *
     * @param string $keyId Identificador da chave
     * @return string Caminho para a chave
     */
    private function getKeyPath(string $keyId): string
    {
        return $this->storageDirectory . $keyId . '.key';
    }
    
    /**
     * Retorna o caminho para uma versão histórica de uma chave
     *
     * @param string $keyId Identificador da chave
     * @param int $version Versão da chave
     * @return string Caminho para a versão histórica da chave
     */
    private function getKeyHistoryPath(string $keyId, int $version): string
    {
        return $this->storageDirectory . $keyId . '.' . $version . '.key';
    }
}
