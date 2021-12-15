<?php

namespace AndrewSvirin\EUSPE;

use AndrewSvirin\EUSPE\Exceptions\GetSignerInfoException;
use AndrewSvirin\EUSPE\Exceptions\GetSignsCountException;
use AndrewSvirin\EUSPE\Exceptions\GetSignTimeException;
use Exception;
use AndrewSvirin\EUSPE\Exceptions\ExtractJKSException;
use AndrewSvirin\EUSPE\Exceptions\ParseCertificatesException;
use AndrewSvirin\EUSPE\Exceptions\ReadPrivateKeyException;
use AndrewSvirin\EUSPE\Exceptions\ResetPrivateKeyException;
use AndrewSvirin\EUSPE\Exceptions\SignDataException;

class Client implements ClientInterface
{

    /**
     * @param  string  $command
     * @param  int|void  $iResult
     * @param  int  $iErrorCode
     * @param  array  $aAcceptableErrorCodes
     * @return bool
     * @throws Exception
     */
    protected function handleResult(
        string $command,
        $iResult,
        int $iErrorCode = null,
        array $aAcceptableErrorCodes = []
    ): bool {
        if (!empty($iErrorCode) && !in_array($iErrorCode, $aAcceptableErrorCodes)) {
            euspe_geterrdescr($iErrorCode, $sErrorDescription);
            $utfEncoding = 'utf-8';
            throw new Exception(
                sprintf(
                    'Result: %s Code: %s Command: %s Error: %s. Check error in EUSignConsts.php by code.',
                    dechex($iResult),
                    dechex($iErrorCode),
                    $command,
                    ($encoding = mb_detect_encoding($sErrorDescription)) && strtolower($encoding) !== $utfEncoding ?
                        mb_convert_encoding($sErrorDescription, $encoding, $utfEncoding) :
                        $sErrorDescription
                )
            );
        }
        return $iResult;
    }

    /**
     * {@inheritdoc}
     * @throws Exception
     */
    public function open(): void
    {
        $this->handleResult('setcharset', euspe_setcharset(EM_ENCODING_UTF8));
        $this->handleResult('init', euspe_init($iErrorCode), $iErrorCode);
    }

    /**
     * {@inheritdoc}
     * @throws Exception
     */
    public function getFileStoreSettings(): array
    {
        $this->handleResult('getfilestoresettings', euspe_getfilestoresettings(
            $sFileStorePath,
            $bCheckCRLs,
            $bAutoRefresh,
            $bOwnCRLsOnly,
            $bFullAndDeltaCRLs,
            $bAutoDownloadCRLs,
            $bSaveLoadedCerts,
            $iExpireTime,
            $iErrorCode
        ), $iErrorCode);
        return [
            'sFileStorePath' => $sFileStorePath,
            'bCheckCRLs' => $bCheckCRLs,
            'bAutoRefresh' => $bAutoRefresh,
            'bOwnCRLsOnly' => $bOwnCRLsOnly,
            'bFullAndDeltaCRLs' => $bFullAndDeltaCRLs,
            'bAutoDownloadCRLs' => $bAutoDownloadCRLs,
            'bSaveLoadedCerts' => $bSaveLoadedCerts,
            'iExpireTime' => $iExpireTime,
        ];
    }

    /**
     * {@inheritdoc}
     * @throws ReadPrivateKeyException
     */
    public function readPrivateKey(string $keyData, string $password): void
    {
        try {
            $this->handleResult(
                'readprivatekeybinary(DAT)',
                euspe_readprivatekeybinary(
                    $keyData,
                    $password,
                    $iErrorCode
                ),
                $iErrorCode,
                [1]
            );
            $this->handleResult(
                'isprivatekeyreaded',
                euspe_isprivatekeyreaded($bIsPrivateKeyRead, $iErrorCode),
                $iErrorCode
            );
            if (!$bIsPrivateKeyRead) {
                throw new Exception('Private key was not read.');
            }
        } catch (Exception $exception) {
            throw new ReadPrivateKeyException($exception->getMessage());
        }
        
    }

    /**
     * {@inheritdoc}
     * @throws ResetPrivateKeyException
     */
    public function resetPrivateKey(): void
    {
        try {
            $this->handleResult('resetprivatekey', euspe_resetprivatekey());
        } catch (Exception $exception) {
            throw new ResetPrivateKeyException($exception->getMessage());
        }
    }

    /**
     * {@inheritdoc}
     * @throws ExtractJKSException
     */
    public function retrieveJKSPrivateKeys(string $keyData): array
    {
        $privateKeys = [];
    
        try {
            $this->handleResult(
                'setruntimeparameter (RESOLVE_OIDS)',
                euspe_setruntimeparameter(EU_RESOLVE_OIDS_PARAMETER, false, $iErrorCode),
                $iErrorCode
            );
            $iKeyIndex = 0;
            while (true) {
                $this->handleResult(
                    'enumjksprivatekeys',
                    euspe_enumjksprivatekeys(
                        $keyData,
                        $iKeyIndex,
                        $sKeyAlias,
                        $iErrorCode
                    ),
                    $iErrorCode,
                    [EU_WARNING_END_OF_ENUM]
                );
                $iKeyIndex++;
                if (EU_WARNING_END_OF_ENUM === $iErrorCode) {
                    break;
                }
                $this->handleResult(
                    'getjksprivatekey',
                    euspe_getjksprivatekey(
                        $keyData,
                        $sKeyAlias,
                        $sPrivateKeyData,
                        $aCertificates,
                        $iErrorCode
                    ),
                    $iErrorCode
                );
                $privateKeys[$sKeyAlias] = $sPrivateKeyData;
            }
            return $privateKeys;
        } catch (Exception $exception) {
            throw new ExtractJKSException($exception->getMessage());
        }
    }

    /**
     * {@inheritdoc}
     * @throws ParseCertificatesException
     */
    public function parseCertificates(array $certs): array
    {
        try {
            $parsed = [];
            foreach ($certs as $certData) {
                $this->handleResult(
                    'parsecert',
                    euspe_parsecert($certData, $certInfo, $iErrorCode),
                    $iErrorCode
                );
                if (EU_SUBJECT_TYPE_END_USER !== $certInfo['subjType']) {
                    continue;
                }
                $parsed[] = $certInfo;
            }
            return $parsed;
        } catch (Exception $exception) {
            throw new ParseCertificatesException($exception->getMessage());
        }
    }
    
    /**
     * {@inheritdoc}
     * @throws ReadPrivateKeyException
     * @throws SignDataException
     */
    public function signData(
        string $data,
        string $keyData,
        string $password,
        bool $isExternalSign = false,
        bool $appendCert = true
    ): string {
        try {
            $this->handleResult('ctxcreate', euspe_ctxcreate($context, $iErrorCode), $iErrorCode);
            $this->handleResult(
                'ctxreadprivatekeybinary',
                euspe_ctxreadprivatekeybinary(
                    $context,
                    $keyData,
                    $password,
                    $pkContext,
                    $iErrorCode
                ),
                $iErrorCode
            );
        } catch (Exception $exception) {
            throw new ReadPrivateKeyException($exception->getMessage());
        }
        
        try {
            $this->handleResult(
                'ctxsigndata',
                euspe_ctxsigndata(
                    $pkContext,
                    EU_CTX_SIGN_DSTU4145_WITH_GOST34311,
                    $data,
                    $isExternalSign,
                    $appendCert,
                    $sSign,
                    $iErrorCode
                ),
                $iErrorCode
            );
            $this->handleResult(
                'ctxisalreadysigned',
                euspe_ctxisalreadysigned(
                    $pkContext,
                    EU_CTX_SIGN_DSTU4145_WITH_GOST34311,
                    $sSign,
                    $bIsAlreadySigned,
                    $iErrorCode
                ),
                $iErrorCode
            );
            if (!$bIsAlreadySigned) {
                throw new Exception('Content not signed properly.');
            }
            
            $this->handleResult('ctxfreeprivatekey', euspe_ctxfreeprivatekey($pkContext));
            $this->handleResult('ctxfree', euspe_ctxfree($context));
            
            return $sSign;
        } catch (Exception $exception) {
            throw new SignDataException($exception->getMessage());
        }
    }
    
    /**
     * {@inheritdoc}
     * @throws GetSignsCountException
     */
    public function getSignsCount(string $sign): int
    {
        try {
            $this->handleResult('getsignscount', euspe_getsignscount($sign, $iCount, $iErrorCode), $iErrorCode);
            return $iCount;
        } catch (Exception $exception) {
            throw new GetSignsCountException($exception->getMessage());
        }
    }
    
    /**
     * {@inheritdoc}
     * @throws GetSignerInfoException
     */
    public function getSignerInfo(string $sign, int $index): array
    {
        try {
            $this->handleResult(
                'getsignerinfoex',
                euspe_getsignerinfoex($index, $sign, $signerInfo, $signerCert, $iErrorCode),
                $iErrorCode
            );
            return $signerInfo;
        } catch (Exception $exception) {
            throw new GetSignerInfoException($exception->getMessage());
        }
    }
    
    /**
     * @param  string  $sign
     * @param  int  $index
     * @return array|null
     * @throws GetSignTimeException
     */
    public function getSignTimeInfo(string $sign, int $index)
    {
        try {
            $this->handleResult(
                'euspe_getsigntimeinfo',
                euspe_getsigntimeinfo($index, $sign, $info, $iErrorCode),
                $iErrorCode
            );
            
            return $info;
        } catch (Exception $exception) {
            throw new GetSignTimeException($exception->getMessage());
        }
    }

    /**
     * {@inheritdoc}
     */
    public function close(): void
    {
        euspe_finalize();
    }

    function envelopData(string $data, array $certs): string
    {
        // TODO: Implement envelopData() method.
        return '';
    }
}
