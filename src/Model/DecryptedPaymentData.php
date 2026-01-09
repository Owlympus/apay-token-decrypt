<?php

namespace Owlympus\ApayTokenDecrypt\Model;

readonly class DecryptedPaymentData
{
    public function __construct(
        public string $applicationPrimaryAccountNumber,
        public string $applicationExpirationDate,
        public string $currencyCode,
        public int $transactionAmount,
        public ?string $cardholderName,
        public string $deviceManufacturerIdentifier,
        public string $paymentDataType,
        public array $paymentData,
        public array $authenticationResponses,
        public ?string $merchantTokenIdentifier,
        public ?string $merchantTokenMetadata,
    ) {
    }
}