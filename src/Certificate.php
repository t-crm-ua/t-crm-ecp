<?php

namespace AndrewSvirin\EUSPE;

use AndrewSvirin\EUSPE\Exceptions\CertificateDirectoryException;
use AndrewSvirin\EUSPE\Exceptions\LoadCertificateException;

class Certificate
{
    
    private $dir;
    
    public function __construct(string $dir)
    {
        $this->dir = $dir;
    }
    
    /**
     * @return string
     * @throws CertificateDirectoryException
     */
    public function getDirRealPath(): string
    {
        if (!($realPath = realpath($this->dir))) {
            throw new CertificateDirectoryException('Can not find certificates dir.');
        }
        return $realPath;
    }
    
    /**
     * Prepare dir for downloading certificates.
     * @throws CertificateDirectoryException
     */
    public function configure()
    {
        if (!file_exists($this->dir) && !(mkdir($this->dir, 0777, true))) {
            throw new CertificateDirectoryException('Can not prepare certificates dir.');
        }
    }
    
    /**
     * Get certificate files.
     * @return array|null
     */
    private function getCerts(): ?array
    {
        $files = scandir($this->dir);
        if (empty($files)) {
            return null;
        }
        $result = [];
        foreach ($files as $file) {
            if ('.cer' === substr($file, -4) && ($certPath = realpath(sprintf('%s/%s', $this->dir, $file)))) {
                $result[] = $certPath;
            }
        }
        return empty($result) ? null : $result;
    }
    
    public function hasCerts(): bool
    {
        return null !== $this->getCerts();
    }
    
    /**
     * @return array
     * @throws LoadCertificateException
     */
    public function loadCerts(): array
    {
        if (!($certFiles = $this->getCerts())) {
            throw new LoadCertificateException('Certificates not found.');
        }
        $certs = [];
        foreach ($certFiles as $certFile) {
            $certs[] = file_get_contents($certFile, FILE_USE_INCLUDE_PATH);
        }
        return $certs;
    }
}
