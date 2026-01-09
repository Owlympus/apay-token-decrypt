<?php

namespace Owlympus\ApayTokenDecrypt\Model;

readonly class EncryptedPaymentData
{
    public function __construct(
        public string $data,
        public string $signature,
        public Header $header,
        public string $version,
    ) {
    }
}