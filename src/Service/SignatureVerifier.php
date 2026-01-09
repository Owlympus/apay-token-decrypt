<?php

namespace Owlympus\ApayTokenDecrypt\Service;

use Owlympus\ApayTokenDecrypt\Exception\SignatureException;
use Owlympus\ApayTokenDecrypt\Model\ApplePayToken;
use Owlympus\ApayTokenDecrypt\Model\EncryptedPaymentData;
use phpseclib3\File\ASN1;

class SignatureVerifier
{
    private const string LEAF_CERTIFICATE_OID = '1.2.840.113635.100.6.29';
    private const string INTERMEDIATE_CERTIFICATE_OID = '1.2.840.113635.100.6.2.14';
    private const string ROOT_G3_PATH = 'certificate/AppleRootCA-G3.cer';
    private const int TIME_LIMIT = 300;

    private ?string $leafCertificatePem = null;
    private ?string $intermediateCertificatePem = null;

    /**
     * @throws SignatureException
     */
    private function checkOIDs(string $signature): void
    {
        $cmsPem =
            "-----BEGIN PKCS7-----\n" .
            chunk_split($signature, 64, PHP_EOL) .
            "-----END PKCS7-----\n";

        $test = openssl_pkcs7_read($cmsPem, $certs);
        if ($test === false) {
            throw new SignatureException(sprintf(
                'Cannot read PKCS7 certificate: %s',
                openssl_error_string(),
            ));
        }

        array_walk($certs, function ($cert) {
            $parsed = openssl_x509_parse($cert);
            if ($parsed === false) {
                throw new SignatureException(sprintf(
                    'Cannot parse X509 certificate: %s',
                    openssl_error_string(),
                ));
            }

            if (array_key_exists(self::LEAF_CERTIFICATE_OID, $parsed['extensions'])) {
                $this->leafCertificatePem = $cert;
            } elseif (array_key_exists(self::INTERMEDIATE_CERTIFICATE_OID, $parsed['extensions'])) {
                $this->intermediateCertificatePem = $cert;
            }
        });

        if ($this->leafCertificatePem === null) {
            throw new SignatureException('The signature dos not contains leaf certificate OID.');
        }
        if ($this->intermediateCertificatePem === null) {
            throw new SignatureException('The signature dos not contains intermediate certificate OID.');
        }
    }

    /**
     * @throws SignatureException
     */
    private function verifyCertificates(): void
    {
        $leafCert = openssl_x509_read($this->leafCertificatePem);
        $intermediateCert = openssl_x509_read($this->intermediateCertificatePem);

        $result = openssl_x509_verify($leafCert, $intermediateCert);
        if ($result !== 1) {
            throw new SignatureException(sprintf('Cannot verify leaf certificate: %s', openssl_error_string()));
        }

        $rootPem =
            "-----BEGIN CERTIFICATE-----\n" .
            chunk_split(base64_encode(file_get_contents(dirname(__DIR__) . '/../' . self::ROOT_G3_PATH)), 64, PHP_EOL) .
            "-----END CERTIFICATE-----\n";

        $rootCert = openssl_x509_read($rootPem);
        if ($rootCert === false) {
            throw new SignatureException(sprintf('Cannot read root certificate: %s', openssl_error_string()));
        }

        $result = openssl_x509_verify($intermediateCert, $rootCert);
        if ($result !== 1) {
            throw new SignatureException('Intermediate certificate verification failed.');
        }
    }

    /**
     * @throws SignatureException
     */
    private function verifyCms(EncryptedPaymentData $paymentData): void
    {
        $signedData =
            base64_decode($paymentData->header->ephemeralPublicKey, true) .
            base64_decode($paymentData->data, true) .
            hex2bin($paymentData->header->transactionId);

        $cmsPem =
            "-----BEGIN PKCS7-----\n" .
            chunk_split($paymentData->signature, 64, PHP_EOL) .
            "-----END PKCS7-----\n";

        $test = openssl_pkcs7_read($cmsPem, $certs);
        if ($test === false) {
            throw new SignatureException(sprintf(
                'Cannot read PKCS7 certificate: %s',
                openssl_error_string(),
            ));
        }

        $asn1 = ASN1::decodeBER(base64_decode($paymentData->signature));
        $digest = $asn1[0]['content'][1]['content'][0]['content'][4]['content'][0]['content'][3]['content'][3]['content'][1]['content'][0]['content'];

        if (!hash_equals(hash('sha256', $signedData, true), $digest)) {
            throw new SignatureException('Invalid digest');
        }

        $certPubKey = trim(ASN1::asn1map(
            $asn1[0]['content'][1]['content'][0]['content'][3]['content'][0]['content'][0]['content'][6],
            ['type' => ASN1::TYPE_ANY, 'implicit' => true],
        )->element);
        $pemFormattedPublicKey =
            "-----BEGIN PUBLIC KEY-----\n" .
            chunk_split(base64_encode($certPubKey), 64, PHP_EOL) .
            "-----END PUBLIC KEY-----\n";

        $signedAttributes = $asn1[0]['content'][1]['content'][0]['content'][4]['content'][0]['content'][3];
        $signedAttr = ASN1::asn1map($signedAttributes, ['type' => ASN1::TYPE_ANY, 'implicit' => true])->element;
        $signedAttr[0] = chr(0x31);

        $verifyResult = openssl_verify(
            data: $signedAttr,
            signature: $asn1[0]['content'][1]['content'][0]['content'][4]['content'][0]['content'][5]['content'],
            public_key: $pemFormattedPublicKey,
            algorithm: OPENSSL_ALGO_SHA256,
        );

        if ($verifyResult === -1) {
            throw new SignatureException(openssl_error_string());
        }

        if ($verifyResult !== 1) {
            throw new SignatureException('Invalid signature');
        }
    }

    /**
     * @throws SignatureException
     */
    private function verifyTime(string $signature): void
    {
        $asn1 = ASN1::decodeBER(base64_decode($signature));
        $timeAttr = $asn1[0]['content'][1]['content'][0]['content'][4]['content'][0]['content'][3]['content'][1]['content'][1]['content'][0];
        $signingTime = ASN1::asn1map($timeAttr, ['type' => ASN1::TYPE_UTC_TIME]);

        if (time() - strtotime($signingTime) > self::TIME_LIMIT) {
            throw new SignatureException('Token expired');
        }
    }

    /**
     * @throws SignatureException
     */
    public function checkIntegrity(ApplePayToken $token, bool $verifyTime = true): void
    {
        $this->checkOIDs($token->paymentData->signature);
        $this->verifyCertificates();
        $this->verifyCms($token->paymentData);
        if ($verifyTime) {
            $this->verifyTime($token->paymentData->signature);
        }
    }
}
