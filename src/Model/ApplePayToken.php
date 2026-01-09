<?php

namespace Owlympus\ApayTokenDecrypt\Model;

readonly class ApplePayToken
{
    public function __construct(
        public string               $transactionIdentifier,
        public EncryptedPaymentData $paymentData,
        public PaymentMethod        $paymentMethod,
    ) {
    }
}
