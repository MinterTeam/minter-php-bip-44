<?php

namespace BIP\Library;

class Helper
{
    /**
     * Encode number to hex
     *
     * @param $number
     * @return string
     */
    public static function hex_encode($number): string
    {
        $hex = gmp_strval(gmp_init($number, 10), 16);
        return (strlen($hex) % 2 != 0) ? '0' . $hex : $hex;
    }

    /**
     * Decode from hex
     *
     * @param string $hex
     * @return string
     */
    public static function hex_decode(string $hex)
    {
        return gmp_strval(gmp_init($hex, 16), 10);
    }

    /**
     * Sha256 and RIPemd160 algorithms
     *
     * @param string $value
     * @return string
     */
    public static function hash160(string $value): string
    {
        $sha = hash('sha256', pack('H*', $value));
        return hash('ripemd160', pack('H*', $sha));
    }

    /**
     * Encode to base58
     *
     * @param $hex
     * @return string
     */
    public static function base58_encode(string $hex): string
    {
        if (strlen($hex) == 0) {
            return '';
        }

        // Convert the hex string to a base10 integer
        $num = gmp_strval(gmp_init($hex, 16), 58);

        // Check that number isn't just 0 - which would be all padding.
        if ($num != '0') {
            $num = strtr(
                $num,
                '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv',
                '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
            );
        } else {
            $num = '';
        }

        // Pad the leading 1's
        $pad = '';
        $n = 0;
        while (substr($hex, $n, 2) == '00') {
            $pad .= '1';
            $n += 2;
        }

        return $pad . $num;
    }
}