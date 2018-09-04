<?php

namespace UIS\EUSPE;

interface ClientInterface
{

    function open(): void;

    function getFileStoreSettings(): array;

    function retrieveKeyAndCertificates(Key $key, Cert $cert, KeyStorage $keyStorage): void;

    function parseCertificates(array $certs): array;

    function signData(string $data, Key $key): string;

    function getSignerCertInfo(string $data): array;

    function hasData(string $data): string;

    function envelopData(string $data, array $certs): string;

    function close(): void;
}