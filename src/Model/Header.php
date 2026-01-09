<?php

namespace Owlympus\ApayTokenDecrypt\Model;

readonly class Header
{
    public function __construct(
        public string $publicKeyHash,
        public string $ephemeralPublicKey,
        public string $transactionId,
    ) {
    }
}