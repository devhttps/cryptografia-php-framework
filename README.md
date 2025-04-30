# Framework de Criptografia PHP

Um framework moderno e seguro para criptografia em PHP, oferecendo métodos para criptografia simétrica, assimétrica, hashing, gerenciamento de chaves e muito mais.

## Recursos

### Criptografia Simétrica
- **AES-256-GCM**: Criptografia autenticada com Galois/Counter Mode
- **AES-256-CBC**: Modo CBC com HMAC para autenticação
- **ChaCha20-Poly1305**: Algoritmo moderno e rápido
- **Camellia-256-GCM**: Alternativa ao AES com segurança equivalente

### Criptografia Assimétrica
- **RSA**: Implementação com padding OAEP para segurança adicional
- **ECC**: Criptografia de curva elíptica, mais eficiente para chaves de tamanho menor
- **ECDH**: Troca de chaves Diffie-Hellman com curvas elípticas

### Hashing Seguro
- **Argon2id**: Algoritmo moderno recomendado para senhas
- **Bcrypt**: Algoritmo tradicional para hashing de senhas
- **HMAC**: Código de autenticação de mensagem baseado em hash

### Gerenciamento de Chaves
- **KeyVault**: Armazenamento seguro de chaves com criptografia
- **Rotação de Chaves**: Sistema para gerenciar versões de chaves
- **Derivação de Chaves**: PBKDF2 e HKDF para derivação segura

### Criptografia de Arquivos
- **SecureFileEncryptor**: Criptografia de arquivos com metadados
- **Streaming**: Processamento eficiente de arquivos grandes
- **Verificação de Integridade**: Autenticação de dados para evitar adulteração

### Criptografia de Banco de Dados
- **DatabaseEncryptor**: Criptografia de campos sensíveis em banco de dados
- **Serialização Segura**: Suporte a tipos complexos de dados
- **Contexto de Autenticação**: Proteção contra ataques de troca de contexto

### Sessões Seguras
- **SecureSessionHandler**: Manipulador de sessão com criptografia
- **Configuração Segura**: Opções recomendadas para cookies e sessões
- **Proteção contra Roubo de Sessão**: Cookies HttpOnly e SameSite

### Integração com Frameworks
- **Laravel**: Adapter para integração com Laravel Encryption e Hashing
- **Outros Frameworks**: Interface extensível para outros frameworks

### Utilitários de Segurança
- **RandomGenerator**: Geração segura de bytes, strings e UUIDs aleatórios
- **SecurityAudit**: Registro e auditoria de operações criptográficas
- **ConstantTime**: Operações em tempo constante para evitar timing attacks

## Requisitos

- PHP 8.1 ou superior
- Extensão OpenSSL
- Extensão Sodium (recomendado)
- Extensão mbstring

## Instalação

\`\`\`bash
composer require vendor/crypto-framework
\`\`\`

## Uso Básico

### Criptografia Simétrica

\`\`\`php
use CryptoFramework\CryptoFacade;

$crypto = new CryptoFacade();

// Gerar uma chave segura
$key = $crypto->generateRandomBytes(32);

// Criptografar dados
$encryptedData = $crypto->encrypt("Dados sensíveis", $key);

// Descriptografar dados
$decryptedData = $crypto->decrypt($encryptedData, $key);
\`\`\`

### Escolha de Algoritmo

\`\`\`php
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
\`\`\`

### Criptografia de Arquivos

\`\`\`php
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
\`\`\`

### Criptografia de Banco de Dados

\`\`\`php
use CryptoFramework\CryptoFacade;
use CryptoFramework\Database\DatabaseEncryptor;

$crypto = new CryptoFacade();
$dbKey = $crypto->generateRandomBytes(32);
$dbEncryptor = new DatabaseEncryptor();

// Criptografar campos sensíveis
$userData = [
    'id' => 1,
    'name' => 'João Silva',
    'email' => 'joao@example.com',
    'credit_card' => '1234-5678-9012-3456'
];

$fieldsToEncrypt = ['email', 'credit_card'];
$encryptedData = $dbEncryptor->encryptArray($userData, $dbKey, $fieldsToEncrypt);

// Armazenar $encryptedData no banco de dados

// Recuperar e descriptografar
$retrievedData = $dbEncryptor->decryptArray($encryptedData, $dbKey, $fieldsToEncrypt);
\`\`\`

### Sessões Seguras

\`\`\`php
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
\`\`\`

### Integração com Laravel

\`\`\`php
use CryptoFramework\CryptoFacade;
use CryptoFramework\Adapters\LaravelAdapter;
use Illuminate\Encryption\Encrypter;
use Illuminate\Hashing\BcryptHasher;

// Criar adapter para Laravel
$encrypter = new Encrypter(base64_decode($appKey), 'AES-256-CBC');
$hasher = new BcryptHasher(['rounds' => 12]);
$laravelAdapter = new LaravelAdapter($encrypter, $hasher);

// Criar CryptoFacade com adapter
$crypto = new CryptoFacade(frameworkAdapter: $laravelAdapter);

// Usar métodos normalmente (serão delegados ao Laravel)
$encryptedData = $crypto->encrypt("Dados sensíveis", "");
$hash = $crypto->hashPassword("senha123");
\`\`\`

## Boas Práticas de Segurança

1. **Gerenciamento de Chaves**: Use o KeyVault para armazenar chaves de forma segura.
2. **Rotação de Chaves**: Rotacione chaves regularmente para limitar o impacto de comprometimento.
3. **Algoritmos Autenticados**: Prefira algoritmos que oferecem autenticação (GCM, Poly1305).
4. **Dados Associados**: Use dados associados (AAD) para vincular o contexto à criptografia.
5. **Auditoria**: Implemente o SecurityAudit para registrar operações criptográficas.
6. **Verificação de Ambiente**: Use checkEnvironmentSecurity() para verificar a segurança do ambiente.
7. **Senhas Fortes**: Use o SecureHasher com Argon2id para hashing de senhas.
8. **Sessões Seguras**: Use o SecureSessionHandler para proteger sessões.

## Recursos Avançados

### Verificação de Segurança do Ambiente

\`\`\`php
use CryptoFramework\CryptoFacade;

$crypto = new CryptoFacade();
$securityCheck = $crypto->checkEnvironmentSecurity();

if (!$securityCheck['php_version_secure']) {
    echo "Atenção: Sua versão do PHP não é considerada segura.\n";
}

if (!$securityCheck['aes_gcm_available']) {
    echo "Atenção: AES-GCM não está disponível neste ambiente.\n";
}
\`\`\`

### Auditoria de Segurança

\`\`\`php
use CryptoFramework\CryptoFacade;
use CryptoFramework\Utils\SecurityAudit;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

// Configurar logger
$logger = new Logger('crypto');
$logger->pushHandler(new StreamHandler('crypto.log', Logger::INFO));

// Criar auditoria de segurança
$securityAudit = new SecurityAudit($logger, 'MinhaApp', 'admin');

// Criar CryptoFacade com auditoria
$crypto = new CryptoFacade(securityAudit: $securityAudit);

// Todas as operações serão registradas no log
$encryptedData = $crypto->encrypt("Dados sensíveis", $key);
\`\`\`

## Licença

Este projeto está licenciado sob a licença MIT - veja o arquivo LICENSE para detalhes.
