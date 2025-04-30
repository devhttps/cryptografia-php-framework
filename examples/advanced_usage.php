<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use CryptoFramework\CryptoFacade;
use CryptoFramework\Factories\SymmetricCryptoFactory;
use CryptoFramework\KeyManagement\KeyVault;
use CryptoFramework\Utils\SecurityAudit;
use CryptoFramework\Database\DatabaseEncryptor;
use CryptoFramework\FileEncryption\SecureFileEncryptor;
use CryptoFramework\Session\SecureSessionHandler;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

// Configurar logger
$logger = new Logger('crypto');
$logger->pushHandler(new StreamHandler(__DIR__ . '/crypto.log', Logger::INFO));

// Criar auditoria de segurança
$securityAudit = new SecurityAudit($logger, 'AdvancedExample', 'admin');

// Criar fábrica de criptografia simétrica
$symmetricFactory = new SymmetricCryptoFactory();

// Obter o algoritmo recomendado
$recommendedAlgorithm = $symmetricFactory->getRecommendedAlgorithm();
echo "Algoritmo recomendado: $recommendedAlgorithm\n";

// Criar cifra simétrica
$cipher = $symmetricFactory->create($recommendedAlgorithm);

// Criar CryptoFacade
$crypto = new CryptoFacade(
    symmetricCrypto: $cipher,
    securityAudit: $securityAudit
);

// Verificar segurança do ambiente
$securityCheck = $crypto->checkEnvironmentSecurity();
echo "Verificação de segurança do ambiente:\n";
foreach ($securityCheck as $key => $value) {
    echo "  $key: " . (is_bool($value) ? ($value ? 'Sim' : 'Não') : $value) . "\n";
}

// Exemplo de criptografia de arquivo
echo "\nCriptografia de arquivo:\n";
$fileKey = $crypto->generateRandomBytes(32);
$inputFile = __FILE__;
$encryptedFile = __DIR__ . '/encrypted_file.enc';
$decryptedFile = __DIR__ . '/decrypted_file.php';

$metadata = [
    'description' => 'Exemplo de arquivo criptografado',
    'created_by' => 'admin',
    'tags' => ['exemplo', 'criptografia', 'arquivo']
];

if ($crypto->encryptFile($inputFile, $encryptedFile, $fileKey, $metadata)) {
    echo "  Arquivo criptografado com sucesso: $encryptedFile\n";
    
    $fileMetadata = $crypto->decryptFile($encryptedFile, $decryptedFile, $fileKey);
    echo "  Arquivo descriptografado com sucesso: $decryptedFile\n";
    echo "  Metadados do arquivo:\n";
    foreach ($fileMetadata as $key => $value) {
        if (is_array($value)) {
            echo "    $key: " . implode(', ', $value) . "\n";
        } else {
            echo "    $key: $value\n";
        }
    }
}

// Exemplo de criptografia de banco de dados
echo "\nCriptografia de banco de dados:\n";
$dbKey = $crypto->generateRandomBytes(32);
$dbEncryptor = new DatabaseEncryptor($cipher);

$userData = [
    'id' => 1,
    'name' => 'João Silva',
    'email' => 'joao@example.com',
    'password' => 'senha123',
    'credit_card' => '1234-5678-9012-3456',
    'address' => 'Rua Exemplo, 123',
    'created_at' => time()
];

$fieldsToEncrypt = ['email', 'credit_card', 'address'];
$encryptedData = $dbEncryptor->encryptArray($userData, $dbKey, $fieldsToEncrypt);

echo "  Dados originais:\n";
print_r($userData);

echo "  Dados criptografados:\n";
print_r($encryptedData);

$decryptedData = $dbEncryptor->decryptArray($encryptedData, $dbKey, $fieldsToEncrypt);

echo "  Dados descriptografados:\n";
print_r($decryptedData);

// Exemplo de sessão segura
echo "\nSessão segura:\n";
$sessionKey = $crypto->generateRandomBytes(32);
$sessionHandler = $crypto->createSessionHandler($sessionKey);

// Configurar sessão
SecureSessionHandler::setup([
    'cookie_lifetime' => 3600,
    'gc_maxlifetime' => 3600
]);

// Registrar manipulador de sessão
session_set_save_handler($sessionHandler, true);

// Iniciar sessão
session_start();

// Armazenar dados na sessão
$_SESSION['user_id'] = 123;
$_SESSION['username'] = 'admin';
$_SESSION['last_login'] = time();

echo "  Dados armazenados na sessão:\n";
print_r($_SESSION);

// Encerrar sessão
session_write_close();

// Limpar arquivos temporários
if (file_exists($encryptedFile)) {
    unlink($encryptedFile);
}

if (file_exists($decryptedFile)) {
    unlink($decryptedFile);
}

echo "\nExemplo concluído com sucesso!\n";
