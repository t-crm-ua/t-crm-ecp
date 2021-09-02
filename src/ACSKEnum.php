<?php

namespace AndrewSvirin\EUSPE;

class ACSKEnum
{
    const PRIVATBANK = 'acsk.privatbank.ua';
    const IDD = 'acskidd.gov.ua';
    const IIT = 'ca.iit.com.ua';
    const K_SYSTEMS = 'ca.ksystems.com.ua';

    const ACKS_TYPES = [
        self::PRIVATBANK => 'АЦСК АТ КБ «ПРИВАТБАНК»',
        self::IDD => 'КНЕДП - ІДД ДПС',
        self::IIT => 'АТ «ІНСТИТУТ ІНФОРМАЦІЙНИХ ТЕХНОЛОГІЙ',
        self::K_SYSTEMS => 'АЦСК ТОВ «Ключові системи»'
    ];
}
