<?php

declare(strict_types=1);

namespace CryptoFramework;

use CryptoFramework\Adapters\FrameworkAdapterInterface;
use CryptoFramework\Database\DatabaseEncryptor;
use CryptoFramework\Exceptions\CryptoException;
use CryptoFramework\Factories\SymmetricCryptoFactory;
use CryptoFramework\FileEncryption\SecureFileEncryptor;
use CryptoFramework\Hashing\SecureHasher;
use CryptoFramework\Interfaces\SymmetricCryptoInterface;
use CryptoFramework\KeyManagement\KeyVault;
use CryptoFramework\Session\SecureSessionHandler;
use CryptoFramework\Symmetric\AES256GCM;
use CryptoFramework\Symmetric\ChaCha20Poly1305;
use CryptoFramework\Utils\RandomGenerator;
use CryptoFramework\Utils\SecurityAudit;

/**
 * Facade para simplificar o uso do framework de criptografia
 */
final class CryptoFacade
{
    private SymmetricCryptoFactory $symmetricFactory;
    private DatabaseEncryptor $databaseEncryptor;
    private SecureFileEncryptor $fileEncryptor;
    
    /**
     * @param SymmetricCryptoInterface|null $symmetricCrypto Cifra simétrica padrão
     * @param SecureHasher|null $hasher Hasher seguro
     * @param KeyVault|null $keyVault Cofre de chaves
     * @param RandomGenerator|null $randomGenerator Gerador de números aleatórios
     * @param SecurityAudit|null $securityAudit Auditoria de segurança
     * @param FrameworkAdapterInterface|null $frameworkAdapter Adapter para framework
     */
    public function __construct(
        private readonly ?SymmetricCryptoInterface $symmetricCrypto = null,
        private readonly ?SecureHasher $hasher = null,
        private readonly ?KeyVault $keyVault = null,
        private readonly ?RandomGenerator $randomGenerator = null,
        private readonly ?SecurityAudit $securityAudit = null,
        private readonly ?FrameworkAdapterInterface $frameworkAdapter = null
    ) {
        $this->symmetricFactory = new SymmetricCryptoFactory($randomGenerator);
        $this->databaseEncryptor = new DatabaseEncryptor($symmetricCrypto ?? new AES256GCM(), $randomGenerator ?? new RandomGenerator());
        $this->fileEncryptor = new SecureFileEncryptor($symmetricCrypto ?? new AES256GCM(), $randomGenerator ?? new RandomGenerator());
    }
    
    /**
     * Criptografa dados usando o algoritmo simétrico padrão
     *
     * @param string $data Dados a serem criptografados
     * @param string $key Chave de criptografia
     * @param string|null $associatedData Dados associados para autenticação adicional
     * @return string Dados criptografados (formato: base64)
     * @throws CryptoException
     */
    public function encrypt(string $data, string $key, ?string $associatedData = null): string
    {
        $this->securityAudit?->logOperation('encrypt', ['data_size' => strlen($data)]);
        
        $cipher = $this->symmetricCrypto ?? new AES256GCM();
        return $cipher->encrypt($data, $key, $associatedData);
    }
    
    /**
     * Descriptografa dados usando o algoritmo simétrico padrão
     *
     * @param string $encryptedData Dados criptografados (formato: base64)
     * @param string $key Chave de criptografia
     * @param string|null $associatedData Dados associados para autenticação adicional
     * @return string Dados descriptografados
     * @throws CryptoException
     */
    public function decrypt(string $encryptedData, string $key, ?string $associatedData = null): string
    {
        $this->securityAudit?->logOperation('decrypt', ['data_size' => strlen($encryptedData)]);
        
        $cipher = $this->symmetricCrypto ?? new AES256GCM();
        return $cipher->decrypt($encryptedData, $key, $associatedData);
    }
    
    /**
     * Criptografa dados usando um algoritmo específico
     *
     * @param string $data Dados a serem criptografados
     * @param string $key Chave de criptografia
     * @param string $algorithm Algoritmo de criptografia
     * @param string|null $associatedData Dados associados para autenticação adicional
     * @return string Dados criptografados (formato: base64)
     * @throws CryptoException
     */
    public function encryptWithAlgorithm(string $data, string $key, string $algorithm, ?string $associatedData = null): string
    {
        $this->securityAudit?->logOperation('encrypt_with_algorithm', [
            'algorithm' => $algorithm,
            'data_size' => strlen($data)
        ]);
        
        $cipher = $this->symmetricFactory->create($algorithm);
        return $cipher->encrypt($data, $key, $associatedData);
    }
    
    /**
     * Descriptografa dados usando um algoritmo específico
     *
     * @param string $encryptedData Dados criptografados (formato: base64)
     * @param string $key Chave de criptografia
     * @param string $algorithm Algoritmo de criptografia
     * @param string|null $associatedData Dados associados para autenticação adicional
     * @return string Dados descriptografados
     * @throws CryptoException
     */
    public function decryptWithAlgorithm(string $encryptedData, string $key, string $algorithm, ?string $associatedData = null): string
    {
        $this->securityAudit?->logOperation('decrypt_with_algorithm', [
            'algorithm' => $algorithm,
            'data_size' => strlen($encryptedData)
        ]);
        
        $cipher = $this->symmetricFactory->create($algorithm);
        return $cipher->decrypt($encryptedData, $key, $associatedData);
    }
    
    /**
     * Criptografa um valor para armazenamento em banco de dados
     *
     * @param mixed $value Valor a ser criptografado
     * @param string $key Chave de criptografia
     * @param string|null $context Contexto para autenticação adicional
     * @return string Valor criptografado (formato: base64)
     * @throws CryptoException
     */
    public function encryptForDatabase(mixed $value, string $key, ?string $context = null): string
    {
        $this->securityAudit?->logOperation('encrypt_for_database', []);
        return $this->databaseEncryptor->encryptValue($value, $key, $context);
    }
    
    /**
     * Descriptografa um valor armazenado em banco de dados
     *
     * @param string $encryptedValue Valor criptografado
     * @param string $key Chave de criptografia
     * @param string|null $context Contexto para autenticação adicional
     * @return mixed Valor descriptografado
     * @throws CryptoException
     */
    public function decryptFromDatabase(string $encryptedValue, string $key, ?string $context = null): mixed
    {
        $this->securityAudit?->logOperation('decrypt_from_database', []);
        return $this->databaseEncryptor->decryptValue($encryptedValue, $key, $context);
    }
    
    /**
     * Criptografa um arquivo
     *
     * @param string $inputFile Caminho para o arquivo de entrada
     * @param string $outputFile Caminho para o arquivo de saída
     * @param string $key Chave de criptografia
     * @param array<string, mixed> $metadata Metadados do arquivo
     * @return bool True se o arquivo foi criptografado com sucesso
     * @throws CryptoException
     */
    public function encryptFile(string $inputFile, string $outputFile, string $key, array $metadata = []): bool
    {
        $this->securityAudit?->logOperation('encrypt_file', ['file' => $inputFile]);
        return $this->fileEncryptor->encryptFile($inputFile, $outputFile, $key, $metadata);
    }
    
    /**
     * Descriptografa um arquivo
     *
     * @param string $inputFile Caminho para o arquivo de entrada
     * @param string $outputFile Caminho para o arquivo de saída
     * @param string $key Chave de criptografia
     * @return array<string, mixed> Metadados do arquivo
     * @throws CryptoException
     */
    public function decryptFile(string $inputFile, string $outputFile, string $key): array
    {
        $this->securityAudit?->logOperation('decrypt_file', ['file' => $inputFile]);
        return $this->fileEncryptor->decryptFile($inputFile, $outputFile, $key);
    }
    
    /**
     * Cria um hash seguro para senha
     *
     * @param string $password Senha a ser hasheada
     * @param array<string, mixed> $options Opções de configuração para o algoritmo
     * @return string Hash da senha
     * @throws CryptoException
     */
    public function hashPassword(string $password, array $options = []): string
    {
        $this->securityAudit?->logOperation('hash_password', []);
        
        if ($this->frameworkAdapter !== null) {
            return $this->frameworkAdapter->hash($password, $options);
        }
        
        $hasher = $this->hasher ?? new SecureHasher();
        return $hasher->hash($password, $options);
    }
    
    /**
     * Verifica se uma senha corresponde a um hash
     *
     * @param string $password Senha a ser verificada
     * @param string $hash Hash para comparação
     * @return bool True se a senha corresponder ao hash
     * @throws CryptoException
     */
    public function verifyPassword(string $password, string $hash): bool
    {
        $this->securityAudit?->logOperation('verify_password', []);
        
        if ($this->frameworkAdapter !== null) {
            return $this->frameworkAdapter->verifyHash($password, $hash);
        }
        
        $hasher = $this->hasher ?? new SecureHasher();
        return $hasher->verify($password, $hash);
    }
    
    /**
     * Gera bytes aleatórios seguros
     *
     * @param int $length Número de bytes a serem gerados
     * @return string Bytes aleatórios
     * @throws CryptoException
     */
    public function generateRandomBytes(int $length): string
    {
        $this->securityAudit?->logOperation('generate_random_bytes', ['length' => $length]);
        
        $generator = $this->randomGenerator ?? new RandomGenerator();
        return $generator->generateBytes($length);
    }
    
    /**
     * Gera uma string aleatória segura
     *
     * @param int $length Comprimento da string
     * @param string $charset Conjunto de caracteres a serem usados
     * @return string String aleatória
     * @throws CryptoException
     */
    public function generateRandomString(int $length, string $charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'): string
    {
        $this->securityAudit?->logOperation('generate_random_string', ['length' => $length]);
        
        $generator = $this->randomGenerator ?? new RandomGenerator();
        return $generator->generateString($length, $charset);
    }
    
    /**
     * Cria um manipulador de sessão seg  $charset);
    }
    
    /**
     * Cria um manipulador de sessão seguro
     *
     * @param string $key Chave de criptografia
     * @param string $savePath Caminho para armazenamento das sessões
     * @return SecureSessionHandler Manipulador de sessão seguro
     * @throws CryptoException
     */
    public function createSessionHandler(string $key, string $savePath = ''): SecureSessionHandler
    {
        $this->securityAudit?->logOperation('create_session_handler', []);
        
        if (empty($savePath)) {
            $savePath = session_save_path() ?: sys_get_temp_dir();
        }
        
        return new SecureSessionHandler($key, $this->symmetricCrypto ?? new AES256GCM(), $this->randomGenerator ?? new RandomGenerator());
    }
    
    /**
     * Armazena uma chave no cofre de chaves
     *
     * @param string $keyId Identificador da chave
     * @param string $key Chave a ser armazenada
     * @param array<string, mixed> $metadata Metadados da chave
     * @return bool True se a chave foi armazenada com sucesso
     * @throws CryptoException
     */
    public function storeKey(string $keyId, string $key, array $metadata = []): bool
    {
        if ($this->keyVault === null) {
            throw new CryptoException('KeyVault não está configurado');
        }
        
        $this->securityAudit?->logOperation('store_key', ['key_id' => $keyId]);
        return $this->keyVault->storeKey($keyId, $key, $metadata);
    }
    
    /**
     * Recupera uma chave do cofre de chaves
     *
     * @param string $keyId Identificador da chave
     * @return string Chave recuperada
     * @throws CryptoException
     */
    public function retrieveKey(string $keyId): string
    {
        if ($this->keyVault === null) {
            throw new CryptoException('KeyVault não está configurado');
        }
        
        $this->securityAudit?->logOperation('retrieve_key', ['key_id' => $keyId]);
        return $this->keyVault->retrieveKey($keyId);
    }
    
    /**
     * Retorna os algoritmos de criptografia simétrica disponíveis
     *
     * @return array<string> Lista de algoritmos disponíveis
     */
    public function getAvailableSymmetricAlgorithms(): array
    {
        return $this->symmetricFactory->getAvailableAlgorithms();
    }
    
    /**
     * Retorna o algoritmo de criptografia simétrica recomendado
     *
     * @return string Algoritmo recomendado
     * @throws CryptoException
     */
    public function getRecommendedSymmetricAlgorithm(): string
    {
        return $this->symmetricFactory->getRecommendedAlgorithm();
    }
    
    /**
     * Verifica se o ambiente atual é seguro para operações criptográficas
     *
     * @return array<string, bool|string> Resultado da verificação
     */
    public function checkEnvironmentSecurity(): array
    {
        $this->securityAudit?->logOperation('check_environment_security', []);
        
        $results = [
            'openssl_version' => OPENSSL_VERSION_TEXT,
            'sodium_available' => extension_loaded('sodium'),
            'secure_random_available' => function_exists('random_bytes'),
            'php_version' => PHP_VERSION,
            'php_version_secure' => version_compare(PHP_VERSION, '8.1.0', '>='),
            'libsodium_version' => defined('SODIUM_LIBRARY_VERSION') ? SODIUM_LIBRARY_VERSION : 'N/A',
        ];
        
        // Verificar se o PHP está em modo seguro
        $results['open_basedir_configured'] = !empty(ini_get('open_basedir'));
        $results['display_errors_off'] = ini_get('display_errors') === '0';
        
        // Verificar se o OpenSSL está usando algoritmos seguros
        $opensslCiphers = openssl_get_cipher_methods();
        $results['aes_gcm_available'] = in_array('aes-256-gcm', $opensslCiphers, true);
        $results['chacha20_available'] = in_array('chacha20-poly1305', $opensslCiphers, true);
        $results['camellia_available'] = in_array('camellia-256-gcm', $opensslCiphers, true);
        
        return $results;
    }
    
    /**
     * Retorna o adapter de framework atual
     *
     * @return FrameworkAdapterInterface|null Adapter de framework
     */
    public function getFrameworkAdapter(): ?FrameworkAdapterInterface
    {
        return $this->frameworkAdapter;
    }
    
    /**
     * Retorna o nome do framework atual
     *
     * @return string|null Nome do framework
     */
    public function getFrameworkName(): ?string
    {
        return $this->frameworkAdapter?->getFrameworkName();
    }
}
