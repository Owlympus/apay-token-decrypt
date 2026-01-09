<?php

namespace Owlympus\ApayTokenDecrypt\Model;

readonly class PaymentMethod
{
    public function __construct(
        public string $displayName,
        public string $type,
        public string $network,
    ) {
    }
}