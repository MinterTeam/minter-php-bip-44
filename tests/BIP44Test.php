<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use BIP\BIP44;

/**
 * Class for testing BIP44Test
 */
final class BIP44Test extends TestCase
{
    /**
     * Valid seed phrase
     */
    const VALID_SEED = [
        '010f73b01bcbe6d18c5f5f84e421945ec11b98e68a5a2d0cee620c98c0ae476c9b3524f58cd0c2715e2a57eaca26aba7913fbf182414ec44155a2c52e47e86ae',
        '1c607522cd878ab0068f906a57f7490604f491ebc3c0d1036cd9fd678076008b410e7c5a3b3594df3c4352590c644fa3fa634690905e790cb591f0dcce4f68ac',
        'c7d310a0f76b3a5d512ad7c904359e0ca39607e6a0ff33f124bf236514337ca3de18c10dbf72fe55884eef3f37011db2329e001a864ad5d1bd89e26dceee0939'
    ];

    /**
     * Valid private keys
     */
    const VALID_PRIVATE_KEYS = [
        '15182befbc4daaa66335cb012795547906c6391b5f90caeb1dadafc6c7c3c21d',
        '59152e4e11b735d58ade6f60f9d77259039fd7eb053dd52fbfe9f280f829ffdd',
        '66deb81d9fa2d0a5470c8d8dfe1273724754b6cc755baf9e0f4d5899baeaa078'
    ];

    /**
     * Valid extended keys ([public, private])
     */
    const VALID_EXTENDED_KEYS = [
        [
            'xpub6Eg5ahu5DUJXTKoMstLF1nK5Zc9svBoiYoVEsLaFGBoCof9ToPLZ1cNC2i7N6QJDiRtWPoXRf732tAi8t33xTFQpYQMa2TxoUYQU6njDXxu', // public
            'xprvA1gjBCNBP6kEEqitmroEeeNM1aKPWj5sBaZe4xAdhrGDvrpKFr2JTp3iBSUhrcWuWRWZEZ5Yb7ogc9oA5vKmPgmw221fhAh8P9oiPjfpHKF'  // private
        ],
        [
            'xpub6F8LvRvGvddDyU8Gp2uR9RS5rzMYetoVMHQLHASst1Ks8bradQtg4At5WgphvQKCNxeqGyroirxsQmsiy3wCM49caHyewP9DM7ojtykVz7Q', // public
            'xprvA28zWvPP6G4vkz3oi1NQnHVMJxX4FS5dz4UjUn3GKfntFoXS5saRWNZbfRudXZiBevcsoB7geFD91TW1E2PJ69XfLfQhD8uXzaMrmzgx8ga'  // private
        ],
        [
            'xpub6FHuZgayTKXouaG1m5PSdeGnWtnKgJ4qVYC5GbnKNePsnRPAqvhtS34qEWSJEpi6xYhDGN9fPiaKRZhR3nhgspyniVRSXPAf3gDnsub5Gjg', // public
            'xprvA2JZAB45cwyWh6BYf3rSGWL3xrwqGqLz8KGUUDNhpJrtud42JPPdtEkMPDdwzxDUh8DbqPS1pVrf2tc1BRTqT5YZqA14uL85sHbm5BSCBqN'  // private
        ]
    ];

    /**
     * Test that correct private key generated from seed
     */
    public function testComputingPrivateKeyFromSeed()
    {
        foreach(self::VALID_SEED as $key => $seed) {
            $HDKey = BIP44::fromMasterSeed($seed)->derive("m/44'/60'/0'/0/0");
            $this->assertEquals(self::VALID_PRIVATE_KEYS[$key], $HDKey->privateKey);

            $HDKey = BIP44::fromMasterSeed($seed)->derive("m/44'/60'/0'/0");
            $this->assertEquals(self::VALID_EXTENDED_KEYS[$key][0], $HDKey->getPublicExtendedKey());
            $this->assertEquals(self::VALID_EXTENDED_KEYS[$key][1], $HDKey->getPrivateExtendedKey());
        }
    }
}
