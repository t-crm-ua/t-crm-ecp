<?php

namespace AndrewSvirin\EUSPE;

use CertificateDirectoryException;
use AndrewSvirin\EUSPE\traits\ExpiredTrait;

class CertificateStorage
{
    
    use ExpiredTrait;
    
    protected $dir;
    
    public function __construct(string $dir)
    {
        $this->dir = $dir;
    }
    
    /**
     * @param  User  $user
     * @return Certificate
     * @throws CertificateDirectoryException
     */
    public function prepare(User $user): Certificate
    {
        $cert = new Certificate("{$this->dir}/{$user->getServerHost()}/{$user->getUserName()}");
        $cert->configure();
        return $cert;
    }
    
}
