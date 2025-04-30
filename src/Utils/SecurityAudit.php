<?php

declare(strict_types=1);

namespace CryptoFramework\Utils;

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Classe para auditoria de segurança
 */
final class SecurityAudit
{
    private LoggerInterface $logger;
    private string $appName;
    private ?string $userId;
    
    /**
     * @param LoggerInterface|null $logger Logger para registro de eventos
     * @param string $appName Nome da aplicação
     * @param string|null $userId ID do usuário atual
     */
    public function __construct(
        ?LoggerInterface $logger = null,
        string $appName = 'CryptoFramework',
        ?string $userId = null
    ) {
        $this->logger = $logger ?? new NullLogger();
        $this->appName = $appName;
        $this->userId = $userId;
    }
    
    /**
     * Registra uma operação criptográfica
     *
     * @param string $operation Nome da operação
     * @param array<string, mixed> $context Contexto da operação
     * @return void
     */
    public function logOperation(string $operation, array $context = []): void
    {
        $logContext = [
            'app' => $this->appName,
            'operation' => $operation,
            'timestamp' => time(),
            'user_id' => $this->userId,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? null,
            'request_id' => $_SERVER['HTTP_X_REQUEST_ID'] ?? uniqid('req_', true),
        ];
        
        $this->logger->info(
            sprintf('Operação criptográfica: %s', $operation),
            array_merge($logContext, $context)
        );
    }
    
    /**
     * Registra uma falha de segurança
     *
     * @param string $message Mensagem de erro
     * @param array<string, mixed> $context Contexto do erro
     * @return void
     */
    public function logSecurityFailure(string $message, array $context = []): void
    {
        $logContext = [
            'app' => $this->appName,
            'timestamp' => time(),
            'user_id' => $this->userId,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? null,
            'request_id' => $_SERVER['HTTP_X_REQUEST_ID'] ?? uniqid('req_', true),
        ];
        
        $this->logger->alert(
            sprintf('Falha de segurança: %s', $message),
            array_merge($logContext, $context)
        );
    }
    
    /**
     * Define o ID do usuário atual
     *
     * @param string|null $userId ID do usuário
     * @return void
     */
    public function setUserId(?string $userId): void
    {
        $this->userId = $userId;
    }
}
