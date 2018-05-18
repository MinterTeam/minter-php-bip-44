<?php

namespace BIP;

class BIP44
{
    /**
     * Password
     */
    const MASTER_SECRET = "Bitcoin seed";

    /**
     * Generate deterministic key from seed phrase
     *
     * @param string $seed
     * @return HDKey
     */
    public static function fromMasterSeed(string $seed): HDKey
    {
        // Generate HMAC hash, and the key/chaincode.
        $I = hash_hmac('sha512', hex2bin($seed), self::MASTER_SECRET);
        $IL = substr($I, 0, 64);
        $IR = substr($I, 64, 64);

        // Return deterministic key
        return new HDKey([
            'privateKey' => $IL,
            'chainCode' => $IR
        ]);
    }
}