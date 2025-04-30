# PHP Cryptography Framework

A modern and secure cryptography framework for PHP, offering methods for symmetric, asymmetric, hashing, key management, and more.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Security Best Practices](#security-best-practices)
- [Advanced Features](#advanced-features)
- [License](#license)
- [Documentação em Português](#documentação-em-português)

## Features

### Symmetric Cryptography
- **AES-256-GCM**: Authenticated encryption with Galois/Counter Mode
- **AES-256-CBC**: CBC mode with HMAC for authentication
- **ChaCha20-Poly1305**: Modern and fast algorithm
- **Camellia-256-GCM**: AES alternative with equivalent security

### Asymmetric Cryptography
- **RSA**: Implementation with OAEP padding for additional security
- **ECC**: Elliptic curve cryptography, more efficient for smaller keys
- **ECDH**: Elliptic curve Diffie-Hellman key exchange

### Secure Hashing
- **Argon2id**: Modern algorithm recommended for passwords
- **Bcrypt**: Traditional algorithm for password hashing
- **HMAC**: Hash-based message authentication code

### Key Management
- **KeyVault**: Secure key storage with encryption
- **Key Rotation**: System for managing key versions
- **Key Derivation**: PBKDF2 and HKDF for secure derivation

### File Encryption
- **SecureFileEncryptor**: File encryption with metadata
- **Streaming**: Efficient processing of large files
- **Integrity Check**: Data authentication to prevent tampering

### Database Encryption
- **DatabaseEncryptor**: Encryption of sensitive fields in the database
- **Secure Serialization**: Support for complex data types
- **Authentication Context**: Protection against context switching attacks

### Secure Sessions
- **SecureSessionHandler**: Encrypted session handler
- **Secure Configuration**: Recommended options for cookies and sessions
- **Session Hijacking Protection**: HttpOnly and SameSite cookies

### Framework Integration
- **Laravel**: Adapter for integration with Laravel Encryption and Hashing
- **Other Frameworks**: Extensible interface for other frameworks

### Security Utilities
- **RandomGenerator**: Secure generation of random bytes, strings, and UUIDs
- **SecurityAudit**: Logging and auditing of cryptographic operations
- **ConstantTime**: Constant-time operations to prevent timing attacks

## Requirements

- PHP 8.1 or higher
- OpenSSL extension
- Sodium extension (recommended)
- mbstring extension

## Installation

\`\`\`bash
composer require vendor/crypto-framework
\`\`\`

## Usage

### Symmetric Cryptography

\`\`\`php
use CryptoFramework\CryptoFacade;

$crypto = new CryptoFacade();

// Generate a secure key
$key = $crypto->generateRandomBytes(32);

// Encrypt data
$encryptedData = $crypto->encrypt("Sensitive data", $key);

// Decrypt data
$decryptedData = $crypto->decrypt($encryptedData, $key);
\`\`\`

### Algorithm Selection

\`\`\`php
use CryptoFramework\CryptoFacade;
use CryptoFramework\Factories\SymmetricCryptoFactory;

// Create symmetric cryptography factory
$factory = new SymmetricCryptoFactory();

// List available algorithms
$algorithms = $factory->getAvailableAlgorithms();
print_r($algorithms);

// Get recommended algorithm
$recommendedAlgorithm = $factory->getRecommendedAlgorithm();

// Encrypt with specific algorithm
$crypto = new CryptoFacade();
$encryptedData = $crypto->encryptWithAlgorithm("Sensitive data", $key, $recommendedAlgorithm);
\`\`\`

### File Encryption

\`\`\`php
use CryptoFramework\CryptoFacade;

$crypto = new CryptoFacade();

// Generate key for file encryption
$fileKey = $crypto->generateRandomBytes(32);

// Encrypt file
$metadata = [
    'description' => 'Confidential document',
    'owner' => 'John Doe',
    'created_at' => time()
];

$crypto->encryptFile('document.pdf', 'document.enc', $fileKey, $metadata);

// Decrypt file
$retrievedMetadata = $crypto->decryptFile('document.enc', 'recovered_document.pdf', $fileKey);
\`\`\`

### Database Encryption

\`\`\`php
use CryptoFramework\CryptoFacade;
use CryptoFramework\Database\DatabaseEncryptor;

$crypto = new CryptoFacade();
$dbKey = $crypto->generateRandomBytes(32);
$dbEncryptor = new DatabaseEncryptor();

// Encrypt sensitive fields
$userData = [
    'id' => 1,
    'name' => 'John Doe',
    'email' => 'john@example.com',
    'credit_card' => '1234-5678-9012-3456'
];

$fieldsToEncrypt = ['email', 'credit_card'];
$encryptedData = $dbEncryptor->encryptArray($userData, $dbKey, $fieldsToEncrypt);

// Store $encryptedData in the database

// Retrieve and decrypt
$retrievedData = $dbEncryptor->decryptArray($encryptedData, $dbKey, $fieldsToEncrypt);
\`\`\`

### Secure Sessions

\`\`\`php
use CryptoFramework\CryptoFacade;
use CryptoFramework\Session\SecureSessionHandler;

$crypto = new CryptoFacade();
$sessionKey = $crypto->generateRandomBytes(32);

// Configure session options
SecureSessionHandler::setup([
    'cookie_lifetime' => 3600,
    'gc_maxlifetime' => 3600
]);

// Create and register session handler
$sessionHandler = $crypto->createSessionHandler($sessionKey);
session_set_save_handler($sessionHandler, true);

// Start session
session_start();

// Use session normally
$_SESSION['user_id'] = 123;
\`\`\`

### Laravel Integration

\`\`\`php
use CryptoFramework\CryptoFacade;
use CryptoFramework\Adapters\LaravelAdapter;
use Illuminate\Encryption\Encrypter;
use Illuminate\Hashing\BcryptHasher;

// Create adapter for Laravel
$encrypter = new Encrypter(base64_decode($appKey), 'AES-256-CBC');
$hasher = new BcryptHasher(['rounds' => 12]);
$laravelAdapter = new LaravelAdapter($encrypter, $hasher);

// Create CryptoFacade with adapter
$crypto = new CryptoFacade(frameworkAdapter: $laravelAdapter);

// Use methods normally (will be delegated to Laravel)
$encryptedData = $crypto->encrypt("Sensitive data", "");
$hash = $crypto->hashPassword("password123");
\`\`\`

## Security Best Practices

1. **Key Management**: Use KeyVault to securely store keys.
2. **Key Rotation**: Rotate keys regularly to limit the impact of compromise.
3. **Authenticated Algorithms**: Prefer algorithms that offer authentication (GCM, Poly1305).
4. **Associated Data**: Use associated data (AAD) to bind context to encryption.
5. **Auditing**: Implement SecurityAudit to log cryptographic operations.
6. **Environment Check**: Use checkEnvironmentSecurity() to verify the security of the environment.
7. **Strong Passwords**: Use SecureHasher with Argon2id for password hashing.
8. **Secure Sessions**: Use SecureSessionHandler to protect sessions.

## Advanced Features

### Environment Security Check

\`\`\`php
use CryptoFramework\CryptoFacade;

$crypto = new CryptoFacade();
$securityCheck = $crypto->checkEnvironmentSecurity();

if (!$securityCheck['php_version_secure']) {
    echo "Warning: Your PHP version is not considered secure.\n";
}

if (!$securityCheck['aes_gcm_available']) {
    echo "Warning: AES-GCM is not available in this environment.\n";
}
\`\`\`

### Security Auditing

\`\`\`php
use CryptoFramework\CryptoFacade;
use CryptoFramework\Utils\SecurityAudit;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

// Configure logger
$logger = new Logger('crypto');
$logger->pushHandler(new StreamHandler('crypto.log', Logger::INFO));

// Create security audit
$securityAudit = new SecurityAudit($logger, 'MyApp', 'admin');

// Create CryptoFacade with auditing
$crypto = new CryptoFacade(securityAudit: $securityAudit);

// All operations will be logged
$encryptedData = $crypto->encrypt("Sensitive data", $key);
\`\`\`

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## Documentação em Português

### Índice

- [Recursos](#recursos)
- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Uso](#uso)
- [Boas Práticas de Segurança](#boas-práticas-de-segurança)
- [Recursos Avançados](#recursos-avançados)
- [Licença](#licença)

### Recursos

#### Criptografia Simétrica
- **AES-256-GCM**: Criptografia autenticada com modo Galois/Counter
- **AES-256-CBC**: Modo CBC com HMAC para autenticação
- **ChaCha20-Poly1305**: Algoritmo moderno e rápido
- **Camellia-256-GCM**: Alternativa ao AES com segurança equivalente

#### Criptografia Assimétrica
- **RSA**: Implementação com padding OAEP para segurança adicional
- **ECC**: Criptografia de curva elíptica, mais eficiente para chaves menores
- **ECDH**: Troca de chaves Diffie-Hellman de curva elíptica

#### Hash Seguro
- **Argon2id**: Algoritmo moderno recomendado para senhas
- **Bcrypt**: Algoritmo tradicional para hash de senhas
- **HMAC**: Código de autenticação de mensagem baseado em hash

#### Gerenciamento de Chaves
- **KeyVault**: Armazenamento seguro de chaves com criptografia
- **Rotação de Chaves**: Sistema para gerenciar versões de chaves
- **Derivação de Chaves**: PBKDF2 e HKDF para derivação segura

#### Criptografia de Arquivos
- **SecureFileEncryptor**: Criptografia de arquivos com metadados
- **Streaming**: Processamento eficiente de arquivos grandes
- **Verificação de Integridade**: Autenticação de dados para prevenir adulteração

#### Criptografia de Banco de Dados
- **DatabaseEncryptor**: Criptografia de campos sensíveis no banco de dados
- **Serialização Segura**: Suporte para tipos de dados complexos
- **Contexto de Autenticação**: Proteção contra ataques de troca de contexto

#### Sessões Seguras
- **SecureSessionHandler**: Manipulador de sessão criptografado
- **Configuração Segura**: Opções recomendadas para cookies e sessões
- **Proteção contra Sequestro de Sessão**: Cookies HttpOnly e SameSite

#### Integração com Frameworks
- **Laravel**: Adaptador para integração com Criptografia e Hash do Laravel
- **Outros Frameworks**: Interface extensível para outros frameworks

#### Utilitários de Segurança
- **RandomGenerator**: Geração segura de bytes aleatórios, strings e UUIDs
- **SecurityAudit**: Registro e auditoria de operações criptográficas
- **ConstantTime**: Operações de tempo constante para prevenir ataques de temporização

### Requisitos

- PHP 8.1 ou superior
- Extensão OpenSSL
- Extensão Sodium (recomendado)
- Extensão mbstring

### Instalação

```bash
composer require vendor/crypto-framework
```

### Uso

#### Criptografia Simétrica

```php
use CryptoFramework\CryptoFacade;

$crypto = new CryptoFacade();

// Gerar uma chave segura
$key = $crypto->generateRandomBytes(32);

// Criptografar dados
$encryptedData = $crypto->encrypt("Dados sensíveis", $key);

// Descriptografar dados
$decryptedData = $crypto->decrypt($encryptedData, $key);
```

#### Seleção de Algoritmo

```php
use CryptoFramework\CryptoFacade;
use CryptoFramework\Factories\SymmetricCryptoFactory;

// Criar fábrica de criptografia simétrica
$factory = new SymmetricCryptoFactory();

// Listar algoritmos disponíveis
$algorithms = $factory->getAvailableAlgorithms();
print_r($algorithms);

// Obter algoritmo recomendado
$recommendedAlgorithm = $factory->getRecommendedAlgorithm();

// Criptografar com algoritmo específico
$crypto = new CryptoFacade();
$encryptedData = $crypto->encryptWithAlgorithm("Dados sensíveis", $key, $recommendedAlgorithm);
```

#### Criptografia de Arquivos

```php
use CryptoFramework\CryptoFacade;

$crypto = new CryptoFacade();

// Gerar chave para criptografia de arquivo
$fileKey = $crypto->generateRandomBytes(32);

// Criptografar arquivo
$metadata = [
    'description' => 'Documento confidencial',
    'owner' => 'João Silva',
    'created_at' => time()
];

$crypto->encryptFile('documento.pdf', 'documento.enc', $fileKey, $metadata);

// Descriptografar arquivo
$retrievedMetadata = $crypto->decryptFile('documento.enc', 'documento_recuperado.pdf', $fileKey);
```

#### Criptografia de Banco de Dados

```php
use CryptoFramework\CryptoFacade;
use CryptoFramework\Database\DatabaseEncryptor;

$crypto = new CryptoFacade();
$dbKey = $crypto->generateRandomBytes(32);
$dbEncryptor = new DatabaseEncryptor();

// Criptografar campos sensíveis
$userData = [
    'id' => 1,
    'name' => 'João Silva',
    'email' => 'joao@exemplo.com',
    'credit_card' => '1234-5678-9012-3456'
];

$fieldsToEncrypt = ['email', 'credit_card'];
$encryptedData = $dbEncryptor->encryptArray($userData, $dbKey, $fieldsToEncrypt);

// Armazenar $encryptedData no banco de dados

// Recuperar e descriptografar
$retrievedData = $dbEncryptor->decryptArray($encryptedData, $dbKey, $fieldsToEncrypt);
```

#### Sessões Seguras

```php
use CryptoFramework\CryptoFacade;
use CryptoFramework\Session\SecureSessionHandler;

$crypto = new CryptoFacade();
$sessionKey = $crypto->generateRandomBytes(32);

// Configurar opções de sessão
SecureSessionHandler::setup([
    'cookie_lifetime' => 3600,
    'gc_maxlifetime' => 3600
]);

// Criar e registrar manipulador de sessão
$sessionHandler = $crypto->createSessionHandler($sessionKey);
session_set_save_handler($sessionHandler, true);

// Iniciar sessão
session_start();

// Usar sessão normalmente
$_SESSION['user_id'] = 123;
```

#### Integração com Laravel

```php
use CryptoFramework\CryptoFacade;
use CryptoFramework\Adapters\LaravelAdapter;
use Illuminate\Encryption\Encrypter;
use Illuminate\Hashing\BcryptHasher;

// Criar adaptador para Laravel
$encrypter = new Encrypter(base64_decode($appKey), 'AES-256-CBC');
$hasher = new BcryptHasher(['rounds' => 12]);
$laravelAdapter = new LaravelAdapter($encrypter, $hasher);

// Criar CryptoFacade com adaptador
$crypto = new CryptoFacade(frameworkAdapter: $laravelAdapter);

// Usar métodos normalmente (serão delegados ao Laravel)
$encryptedData = $crypto->encrypt("Dados sensíveis", "");
$hash = $crypto->hashPassword("senha123");
```

### Boas Práticas de Segurança

1. **Gerenciamento de Chaves**: Use KeyVault para armazenar chaves de forma segura.
2. **Rotação de Chaves**: Rotacione chaves regularmente para limitar o impacto de comprometimento.
3. **Algoritmos Autenticados**: Prefira algoritmos que ofereçam autenticação (GCM, Poly1305).
4. **Dados Associados**: Use dados associados (AAD) para vincular contexto à criptografia.
5. **Auditoria**: Implemente SecurityAudit para registrar operações criptográficas.
6. **Verificação de Ambiente**: Use checkEnvironmentSecurity() para verificar a segurança do ambiente.
7. **Senhas Fortes**: Use SecureHasher com Argon2id para hash de senhas.
8. **Sessões Seguras**: Use SecureSessionHandler para proteger sessões.

### Recursos Avançados

#### Verificação de Segurança do Ambiente

```php
use CryptoFramework\CryptoFacade;

$crypto = new CryptoFacade();
$securityCheck = $crypto->checkEnvironmentSecurity();

if (!$securityCheck['php_version_secure']) {
    echo "Aviso: Sua versão do PHP não é considerada segura.\n";
}

if (!$securityCheck['aes_gcm_available']) {
    echo "Aviso: AES-GCM não está disponível neste ambiente.\n";
}
```

#### Auditoria de Segurança

```php
use CryptoFramework\CryptoFacade;
use CryptoFramework\Utils\SecurityAudit;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

// Configurar logger
$logger = new Logger('crypto');
$logger->pushHandler(new StreamHandler('crypto.log', Logger::INFO));

// Criar auditoria de segurança
$securityAudit = new SecurityAudit($logger, 'MeuApp', 'admin');

// Criar CryptoFacade com auditoria
$crypto = new CryptoFacade(securityAudit: $securityAudit);

// Todas as operações serão registradas
$encryptedData = $crypto->encrypt("Dados sensíveis", $key);
```

### Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo LICENSE para detalhes.
