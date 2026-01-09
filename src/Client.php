<?php declare(strict_types=1);

namespace Owlympus\ApayTokenDecrypt;

use JsonException;
use OpenSSLAsymmetricKey;
use Owlympus\ApayTokenDecrypt\Exception\DecryptionException;
use Owlympus\ApayTokenDecrypt\Exception\KeysException;
use Owlympus\ApayTokenDecrypt\Exception\SignatureException;
use Owlympus\ApayTokenDecrypt\Model\ApplePayToken;
use Owlympus\ApayTokenDecrypt\Model\DecryptedPaymentData;
use Owlympus\ApayTokenDecrypt\Model\EncryptedPaymentData;
use Owlympus\ApayTokenDecrypt\Model\Header;
use Owlympus\ApayTokenDecrypt\Model\PaymentMethod;
use Owlympus\ApayTokenDecrypt\Service\PaymentDataExtractor;
use Owlympus\ApayTokenDecrypt\Service\SignatureVerifier;

readonly class Client
{
    private SignatureVerifier $signatureVerifier;
    private PaymentDataExtractor $paymentDataExtractor;

    public function __construct(
        private OpenSSLAsymmetricKey $privateKey,
        private string               $merchantId,
    ) {
        $this->signatureVerifier = new SignatureVerifier();
        $this->paymentDataExtractor = new PaymentDataExtractor();
    }

    /**
     * @throws JsonException
     */
    private function decodeToken(string $token): ApplePayToken
    {
        $decodedToken = json_decode(
            json: $token,
            associative: true,
            flags: JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_LINE_TERMINATORS | JSON_UNESCAPED_UNICODE,
        );

        return new ApplePayToken(
            transactionIdentifier: $decodedToken['transactionIdentifier'],
            paymentData: new EncryptedPaymentData(
                data: $decodedToken['paymentData']['data'],
                signature: $decodedToken['paymentData']['signature'],
                header: new Header(
                    publicKeyHash: $decodedToken['paymentData']['header']['publicKeyHash'],
                    ephemeralPublicKey: $decodedToken['paymentData']['header']['ephemeralPublicKey'],
                    transactionId: $decodedToken['paymentData']['header']['transactionId'],
                ),
                version: $decodedToken['paymentData']['version'],
            ),
            paymentMethod: new PaymentMethod(
                displayName: $decodedToken['paymentMethod']['displayName'],
                type: $decodedToken['paymentMethod']['type'],
                network: $decodedToken['paymentMethod']['network'],
            ),
        );
    }

    /**
     * @throws KeysException
     * @throws JsonException
     * @throws DecryptionException
     * @throws SignatureException
     */
    public function decryptToken(string $rawToken, bool $verifyTime = true): DecryptedPaymentData
    {
        $token = $this->decodeToken($rawToken);

        $this->signatureVerifier->checkIntegrity($token, $verifyTime);

        return $this->paymentDataExtractor->extract(
            privateKey: $this->privateKey,
            merchantId: $this->merchantId,
            token: $token,
        );
    }
}
