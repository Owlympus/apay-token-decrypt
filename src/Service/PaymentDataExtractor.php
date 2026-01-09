<?php

namespace Owlympus\ApayTokenDecrypt\Service;

use JsonException;
use OpenSSLAsymmetricKey;
use Owlympus\ApayTokenDecrypt\Exception\DecryptionException;
use Owlympus\ApayTokenDecrypt\Exception\KeysException;
use Owlympus\ApayTokenDecrypt\Model\ApplePayToken;
use Owlympus\ApayTokenDecrypt\Model\DecryptedPaymentData;

class PaymentDataExtractor
{
    private const string IV = '00000000000000000000000000000000';
    private const string CYPHER = 'AES-256-GCM';

    /**
     * @throws KeysException
     */
    public function extractRawPublicKey(string $ephemeralPublicKey): string
    {
        if (strlen($ephemeralPublicKey) === 65 && $ephemeralPublicKey[0] === "\x04") {
            return $ephemeralPublicKey;
        }

        if (strlen($ephemeralPublicKey) > 65) {
            for ($i = 0; $i < strlen($ephemeralPublicKey) - 64; $i++) {
                if ($ephemeralPublicKey[$i] === "\x04") {
                    $remainingLength = strlen($ephemeralPublicKey) - $i;
                    if ($remainingLength >= 65) {
                        return substr($ephemeralPublicKey, $i);
                    }
                }
            }
        }

        throw new KeysException('Unable to extract raw public key from ephemeral key data');
    }

    /**
     * @throws KeysException
     */
    public function computeSharedSecret(string $rawEphemeralKey, \OpenSSLAsymmetricKey $merchantPrivateKey): string
    {
        $ephemeralKeyPem = $this->createEphemeralKeyPEM(
            substr($rawEphemeralKey, 1, 32),
            substr($rawEphemeralKey, 33, 32),
        );

        $ephemeralPublicKey = openssl_pkey_get_public($ephemeralKeyPem);
        if ($ephemeralPublicKey === false) {
            throw new KeysException(sprintf('Failed to create ephemeral public key: %s', openssl_error_string()));
        }

        $sharedSecret = openssl_pkey_derive($ephemeralPublicKey, $merchantPrivateKey);
        if ($sharedSecret === false) {
            throw new KeysException(sprintf('ECDH computation failed: %s', openssl_error_string()));
        }

        return bin2hex($sharedSecret);
    }

    private function createEphemeralKeyPEM(string $x, string $y): string
    {
        $publicKeyInfo = sprintf(
            "%s%s\x04%s%s",
            pack('H*', '301306072a8648ce3d020106082a8648ce3d030107'),
            pack('H*', '034200'),
            $x,
            $y,
        );
        $totalLength = strlen($publicKeyInfo);

        $sequence = sprintf(
            "%s%s%s",
            pack('H*', $totalLength < 128 ? '30' : '3081'),
            chr($totalLength),
            $publicKeyInfo,
        );

        return
            "-----BEGIN PUBLIC KEY-----\n" .
            chunk_split(base64_encode($sequence), 64, PHP_EOL) .
            "-----END PUBLIC KEY-----\n";
    }

    private function extractPassphrase(string $sharedSecret, string $merchantId): string
    {
        $hash = hash_init('sha256');
        hash_update($hash, pack('H*', '00000001'));
        hash_update($hash, hex2bin($sharedSecret));
        hash_update(
            $hash,
            sprintf(
                "\x0d%s%s%s",
                'id-aes256-GCM',
                'Apple',
                hash('sha256', $merchantId, true),
            ),
        );

        $derivedKey = hash_final($hash, true);
        return substr($derivedKey, 0, 32);
    }

    /**
     * @throws KeysException
     * @throws DecryptionException
     * @throws JsonException
     */
    public function extract(OpenSSLAsymmetricKey $privateKey, string $merchantId, ApplePayToken $token): DecryptedPaymentData
    {
        $rawEphemeralKey = $this->extractRawPublicKey(base64_decode($token->paymentData->header->ephemeralPublicKey));
        $passphrase = $this->extractPassphrase(
            $this->computeSharedSecret($rawEphemeralKey, $privateKey),
            $merchantId,
        );

        $encryptedData = base64_decode($token->paymentData->data);

        $decryptedData = openssl_decrypt(
            data: substr($encryptedData, 0, -16),
            cipher_algo: self::CYPHER,
            passphrase: $passphrase,
            options: OPENSSL_RAW_DATA,
            iv: hex2bin(self::IV),
            tag: substr($encryptedData, -16),
        );

        if ($decryptedData === false) {
            throw new DecryptionException(
                sprintf('AES-GCM decryption failed: %s', openssl_error_string())
            );
        }

        $data = json_decode(
            json: $decryptedData,
            associative: true,
            flags: JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_LINE_TERMINATORS | JSON_UNESCAPED_UNICODE,
        );

        return new DecryptedPaymentData(
            applicationPrimaryAccountNumber: $data['applicationPrimaryAccountNumber'],
            applicationExpirationDate: $data['applicationExpirationDate'],
            currencyCode: $data['currencyCode'],
            transactionAmount: $data['transactionAmount'],
            cardholderName: $data['cardholderName'] ?? null,
            deviceManufacturerIdentifier: $data['deviceManufacturerIdentifier'],
            paymentDataType: $data['paymentDataType'],
            paymentData: $data['paymentData'],
            authenticationResponses: $data['authenticationResponses'] ?? [],
            merchantTokenIdentifier: $data['merchantTokenIdentifier'] ?? null,
            merchantTokenMetadata: $data['merchantTokenMetadata'] ?? null,
        );
    }
}
