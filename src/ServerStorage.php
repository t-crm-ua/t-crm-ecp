<?php

namespace AndrewSvirin\EUSPE;

use ACSKServerException;
use CertificateDirectoryException;
use AndrewSvirin\EUSPE\traits\ExpiredTrait;
use ServerDirectoryException;

class ServerStorage
{
    
    use ExpiredTrait;
    
    protected $dir;
    
    public function __construct(string $settingsDir)
    {
        $this->dir = $settingsDir;
    }
    
    /**
     * Host is allowed from the list.
     * @param  string  $host
     * @return bool
     */
    public static function verifyHost(string $host): bool
    {
        return in_array($host, array_keys(ACSKEnum::ACKS_TYPES));
    }
    
    /**
     * Prepare server connection for user certificates.
     * Check folders and prepare eusphpe config.
     * @param  User  $user
     * @param  Certificate  $cert
     * @return Server
     * @throws ACSKServerException
     * @throws CertificateDirectoryException
     * @throws ServerDirectoryException
     */
    public function prepare(User $user, Certificate $cert): Server
    {
        $server = new Server("{$this->dir}/{$user->getServerHost()}/{$user->getUserName()}");
        if (!ServerStorage::verifyHost($user->getServerHost())) {
            throw new ACSKServerException(
                sprintf(
                    'Server name %s is out of available list. Setup you server config first.',
                    $user->getServerHost()
                )
            );
        }
        $server->configure();
        if (!file_exists($server->getOSPLMConfigPath())) {
            // Prepare server configuration from template.
            $template = file_get_contents($this->getTemplatePath($user->getServerHost()));
            $content = str_replace('{dir}', $cert->getDirRealPath(), $template);
            file_put_contents($server->getOSPLMConfigPath(), $content);
            file_put_contents($server->getOSPCUConfigPath(), '');
        }
        return $server;
    }
    
    /**
     * @param  string  $serverName
     * @return string
     * @throws ACSKServerException
     */
    public function getTemplatePath(string $serverName): string
    {
        $path = sprintf('%s/servers/%s.dist.ini', __DIR__, $serverName);
        if (!file_exists($path)) {
            throw new ACSKServerException('Missing template file osplm.ini');
        }
        return $path;
    }
    
}
