<?php

declare(strict_types=1);

namespace CryptoFramework\FileEncryption;

use CryptoFramework\Exceptions\CryptoException;
use CryptoFramework\Exceptions\DecryptionException;
use CryptoFramework\Interfaces\SymmetricCryptoInterface;
use CryptoFramework\Symmetric\AES256GCM;
use CryptoFramework\Utils\RandomGenerator;

/**
 * Classe para criptografia segura de arquivos
 */
final class SecureFileEncryptor
{
    private const BUFFER_SIZE = 1024 * 1024; // 1MB
    private const HEADER_MAGIC = 'SECFILE';
    private const HEADER_VERSION = 1;
    
    /**
     * @param SymmetricCryptoInterface $cipher Cifra para criptografia
     * @param RandomGenerator $randomGenerator Gerador de números aleatórios
     */
    public function __construct(
        private readonly SymmetricCryptoInterface $cipher = new AES256GCM(),
        private readonly RandomGenerator $randomGenerator = new RandomGenerator()
    ) {
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
        if (!file_exists($inputFile)) {
            throw new CryptoException("Arquivo de entrada não encontrado: $inputFile");
        }
        
        try {
            $inputHandle = fopen($inputFile, 'rb');
            $outputHandle = fopen($outputFile, 'wb');
            
            if ($inputHandle === false || $outputHandle === false) {
                throw new CryptoException("Falha ao abrir arquivos");
            }
            
            // Gerar ID único para o arquivo
            $fileId = $this->randomGenerator->generateUUID();
            
            // Preparar metadados
            $metadata['file_id'] = $fileId;
            $metadata['created_at'] = time();
            $metadata['original_size'] = filesize($inputFile);
            $metadata['original_name'] = basename($inputFile);
            
            // Serializar metadados
            $metadataJson = json_encode($metadata);
            if ($metadataJson === false) {
                throw new CryptoException("Falha ao serializar metadados");
            }
            
            // Criptografar metadados
            $encryptedMetadata = $this->cipher->encrypt($metadataJson, $key);
            
            // Escrever cabeçalho
            $header = pack(
                'a7Cv',
                self::HEADER_MAGIC,
                self::HEADER_VERSION,
                strlen($encryptedMetadata)
            );
            
            fwrite($outputHandle, $header);
            fwrite($outputHandle, $encryptedMetadata);
            
            // Processar o arquivo em blocos
            while (!feof($inputHandle)) {
                $data = fread($inputHandle, self::BUFFER_SIZE);
                if ($data === false) {
                    throw new CryptoException("Falha ao ler arquivo de entrada");
                }
                
                if (strlen($data) > 0) {
                    $encryptedData = $this->cipher->encrypt($data, $key, $fileId);
                    $blockSize = strlen($encryptedData);
                    
                    // Escrever tamanho do bloco e dados criptografados
                    fwrite($outputHandle, pack('N', $blockSize));
                    fwrite($outputHandle, $encryptedData);
                }
            }
            
            // Fechar arquivos
            fclose($inputHandle);
            fclose($outputHandle);
            
            return true;
        } catch (\Exception $e) {
            // Limpar arquivo de saída em caso de erro
            if (isset($outputHandle) && $outputHandle !== false) {
                fclose($outputHandle);
                if (file_exists($outputFile)) {
                    unlink($outputFile);
                }
            }
            
            if (isset($inputHandle) && $inputHandle !== false) {
                fclose($inputHandle);
            }
            
            throw new CryptoException("Erro ao criptografar arquivo: " . $e->getMessage(), previous: $e);
        }
    }
    
    /**
     * Descriptografa um arquivo
     *
     * @param string $inputFile Caminho para o arquivo de entrada
     * @param string $outputFile Caminho para o arquivo de saída
     * @param string $key Chave de criptografia
     * @return array<string, mixed> Metadados do arquivo
     * @throws CryptoException|DecryptionException
     */
    public function decryptFile(string $inputFile, string $outputFile, string $key): array
    {
        if (!file_exists($inputFile)) {
            throw new CryptoException("Arquivo criptografado não encontrado: $inputFile");
        }
        
        try {
            $inputHandle = fopen($inputFile, 'rb');
            $outputHandle = fopen($outputFile, 'wb');
            
            if ($inputHandle === false || $outputHandle === false) {
                throw new CryptoException("Falha ao abrir arquivos");
            }
            
            // Ler cabeçalho
            $header = fread($inputHandle, 9);
            if ($header === false || strlen($header) < 9) {
                throw new CryptoException("Arquivo criptografado inválido: cabeçalho incompleto");
            }
            
            $headerData = unpack('a7magic/Cversion/vmetadata_size', $header);
            if ($headerData === false || $headerData['magic'] !== self::HEADER_MAGIC) {
                throw new CryptoException("Arquivo criptografado inválido: assinatura incorreta");
            }
            
            if ($headerData['version'] !== self::HEADER_VERSION) {
                throw new CryptoException("Versão de arquivo não suportada: " . $headerData['version']);
            }
            
            // Ler metadados criptografados
            $encryptedMetadata = fread($inputHandle, $headerData['metadata_size']);
            if ($encryptedMetadata === false || strlen($encryptedMetadata) < $headerData['metadata_size']) {
                throw new CryptoException("Arquivo criptografado inválido: metadados incompletos");
            }
            
            // Descriptografar metadados
            $metadataJson = $this->cipher->decrypt($encryptedMetadata, $key);
            $metadata = json_decode($metadataJson, true);
            
            if (!is_array($metadata) || !isset($metadata['file_id'])) {
                throw new CryptoException("Metadados inválidos");
            }
            
            $fileId = $metadata['file_id'];
            
            // Processar o arquivo em blocos
            while (!feof($inputHandle)) {
                // Ler tamanho do bloco
                $blockSizeData = fread($inputHandle, 4);
                if ($blockSizeData === false || strlen($blockSizeData) < 4) {
                    break; // Fim do arquivo
                }
                
                $blockSize = unpack('N', $blockSizeData)[1];
                
                // Ler bloco criptografado
                $encryptedData = fread($inputHandle, $blockSize);
                if ($encryptedData === false || strlen($encryptedData) < $blockSize) {
                    throw new CryptoException("Arquivo criptografado inválido: dados incompletos");
                }
                
                // Descriptografar bloco
                $data = $this->cipher->decrypt($encryptedData, $key, $fileId);
                
                // Escrever dados descriptografados
                fwrite($outputHandle, $data);
            }
            
            // Fechar arquivos
            fclose($inputHandle);
            fclose($outputHandle);
            
            return $metadata;
        } catch (\Exception $e) {
            // Limpar arquivo de saída em caso de erro
            if (isset($outputHandle) && $outputHandle !== false) {
                fclose($outputHandle);
                if (file_exists($outputFile)) {
                    unlink($outputFile);
                }
            }
            
            if (isset($inputHandle) && $inputHandle !== false) {
                fclose($inputHandle);
            }
            
            throw new CryptoException("Erro ao descriptografar arquivo: " . $e->getMessage(), previous: $e);
        }
    }
    
    /**
     * Verifica se um arquivo está criptografado
     *
     * @param string $file Caminho para o arquivo
     * @return bool True se o arquivo estiver criptografado
     */
    public function isEncryptedFile(string $file): bool
    {
        if (!file_exists($file)) {
            return false;
        }
        
        try {
            $handle = fopen($file, 'rb');
            if ($handle === false) {
                return false;
            }
            
            $header = fread($handle, 7);
            fclose($handle);
            
            return $header === self::HEADER_MAGIC;
        } catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * Lê os metadados de um arquivo criptografado sem descriptografá-lo
     *
     * @param string $file Caminho para o arquivo
     * @param string $key Chave de criptografia
     * @return array<string, mixed> Metadados do arquivo
     * @throws CryptoException
     */
    public function readFileMetadata(string $file, string $key): array
    {
        if (!file_exists($file)) {
            throw new CryptoException("Arquivo não encontrado: $file");
        }
        
        try {
            $handle = fopen($file, 'rb');
            if ($handle === false) {
                throw new CryptoException("Falha ao abrir arquivo");
            }
            
            // Ler cabeçalho
            $header = fread($handle, 9);
            if ($header === false || strlen($header) < 9) {
                throw new CryptoException("Arquivo criptografado inválido: cabeçalho incompleto");
            }
            
            $headerData = unpack('a7magic/Cversion/vmetadata_size', $header);
            if ($headerData === false || $headerData['magic'] !== self::HEADER_MAGIC) {
                throw new CryptoException("Arquivo criptografado inválido: assinatura incorreta");
            }
            
            // Ler metadados criptografados
            $encryptedMetadata = fread($handle, $headerData['metadata_size']);
            fclose($handle);
            
            if ($encryptedMetadata === false || strlen($encryptedMetadata) < $headerData['metadata_size']) {
                throw new CryptoException("Arquivo criptografado inválido: metadados incompletos");
            }
            
            // Descriptografar metadados
            $metadataJson = $this->cipher->decrypt($encryptedMetadata, $key);
            $metadata = json_decode($metadataJson, true);
            
            if (!is_array($metadata)) {
                throw new CryptoException("Metadados inválidos");
            }
            
            return $metadata;
        } catch (\Exception $e) {
            throw new CryptoException("Erro ao ler metadados: " . $e->getMessage(), previous: $e);
        }
    }
}
