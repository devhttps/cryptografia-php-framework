<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use CryptoFramework\CryptoFacade;
use CryptoFramework\KeyManagement\KeyVault;
use CryptoFramework\Utils\SecurityAudit;
use Psr\Log\LoggerInterface;

// Criar uma instância do logger (exemplo com Monolog)
$logger = new \Monolog\Logger('crypto');
$logger->pushHandler(new \Monolog\Handler\StreamHandler(__DIR__ . '/crypto.log', \Monolog\Logger::INFO));

// Criar uma instância do SecurityAudit
$securityAudit = new SecurityAudit($logger, 'ExampleApp', 'user123');

// Criar uma instância do CryptoFacade
$crypto = new CryptoFacade(securityAudit: $securityAudit);

echo "=== Exemplo Básico de Uso do Framework de Criptografia ===\n\n";

// Exemplo de criptografia simétrica
echo "Criptografia Simétrica (AES-256-GCM):\n";
$key = $crypto->generateRandomBytes(32);
$data = "Dados sensíveis que precisam ser protegidos";
$encrypted = $crypto->encryptAES($data, $key);
$decrypted = $crypto->decryptAES($encrypted, $key);

echo "Dados originais: $data\n";
echo "Dados criptografados: $encrypted\n";
echo "Dados descriptografados: $decrypted\n\n";

// Exemplo de hashing de senha
echo "Hashing de Senha (Argon2id):\n";
$password = "senha123";
$hash = $crypto->hashPassword($password);
$isValid = $crypto->verifyPassword($password, $hash);

echo "Senha: $password\n";
echo "Hash: $hash\n";
echo "Verificação: " . ($isValid ? "Válida" : "Inválida") . "\n\n";

// Exemplo de criptografia assimétrica
echo "Criptografia Assimétrica (RSA):\n";
$keyPair = $crypto->generateRSAKeyPair(2048);
$rsaData = "Mensagem secreta para criptografia RSA";
$rsaEncrypted = $crypto->encryptRSA($keyPair['public'], $rsaData);
$rsaDecrypted = $crypto->decryptRSA($keyPair['private'], $rsaEncrypted);

echo "Dados originais: $rsaData\n";
echo "Dados criptografados: $rsaEncrypted\n";
echo "Dados descriptografados: $rsaDecrypted\n\n";

// Exemplo de assinatura digital
echo "Assinatura Digital (RSA):\n";
$message = "Esta mensagem precisa ser autenticada";
$signature = $crypto->sign($keyPair['private'], $message);
$isValidSignature = $crypto->verify($keyPair['public'], $message, $signature);

echo "Mensagem: $message\n";
echo "Assinatura: $signature\n";
echo "Verificação: " . ($isValidSignature ? "Válida" : "Inválida") . "\n\n";

// Exemplo de KeyVault
echo "Armazenamento Seguro de Chaves (KeyVault):\n";
$masterKey = $crypto->generateRandomBytes(32);
$keyVault = new KeyVault($masterKey, __DIR__ . '/keys');
$cryptoWithVault = new CryptoFacade(keyVault: $keyVault);

$apiKey = $crypto->generateRandomBytes(32);
$keyId = 'api-key-' . time();

$cryptoWithVault->storeKey($keyId, $apiKey, ['purpose' => 'API Authentication']);
$retrievedKey = $cryptoWithVault->retrieveKey($keyId);

echo "Key ID: $keyId\n";
echo "Chave armazenada e recuperada com sucesso: " . (hash_equals($apiKey, $retrievedKey) ? "Sim" : "Não") . "\n\n";

// Verificação de segurança do ambiente
echo "Verificação de Segurança do Ambiente:\n";
$securityCheck = $crypto->checkEnvironmentSecurity();

echo "PHP Version: " . $securityCheck['php_version'] . "\n";
echo "OpenSSL Version: " . $securityCheck['openssl_version'] . "\n";
echo "Sodium Available: " . ($securityCheck['sodium_available'] ? "Yes" : "No") . "\n";
echo "AES-GCM Available: " . ($securityCheck['aes_gcm_available'] ? "Yes" : "No") . "\n";
echo "ChaCha20 Available: " . ($securityCheck['chacha20_available'] ? "Yes" : "No") . "\n";

echo "\n=== Fim do Exemplo ===\n";
