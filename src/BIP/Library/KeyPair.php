<?php

namespace BIP\Library;

use BN\BN;
use Elliptic\EC\KeyPair as ECKeyPair;

/**
 * Class KeyPair
 * @package BIP\Library
 */
class KeyPair extends ECKeyPair
{
    /**
     * Return BN with adding tweak
     *
     * @param string $privateKey
     * @param string $tweak
     * @param string $enc
     * @return BN
     * @throws \Exception
     */
    public function privateKeyTweakAdd(string $privateKey, string $tweak, string $enc): BN
    {
        $bn = new BN($tweak, $enc);

        if ($bn->cmp($this->ec->n) >= 0) {
            throw new \Exception('EC private key tweak add failed');
        }

        $bn->iadd(new BN($privateKey, $enc));
        if ($bn->cmp($this->ec->n) >= 0) {
            $bn->isub($this->ec->n);
        }

        if ($bn->isZero()) {
            throw new \Exception('EC private key tweak add failed');
        }

        return $bn;
    }

    /*
    public function publicKeyTweakAdd(string $publicKey, string $tweak, string $enc)
    {
        $pair = $this->loadPublicKey($publicKey);
        if ($pair === null) {
            throw new \Exception('Public key parse failed');
        }

        $tweak = new BN($tweak, $enc);
        if ($tweak->cmp($this->ec->n) >= 0) {
            throw new \Exception('Public key tweak add failed');
        }

        //$this->ec->g->mul($tweak)->add($pair->pub);
    }

    protected function loadPublicKey(string $publicKey)
    {
        $first = substr($publicKey, 0, 2);

        if (in_array($first, ['02', '03']) && strlen($publicKey) === 66) {
            return $this->loadCompressedPublicKey($first, substr($publicKey, -64), 'hex');
        }

        if (in_array($first, ['04', '06', '07']) && strlen($publicKey) === 130) {
            return $this->loadUncompressedPublicKey($first, substr($publicKey, 2, 66), substr($publicKey, 66, 130), 'hex');
        }

        return null;
    }

    protected function loadUncompressedPublicKey(string $first, string $x, string $y, string $enc)
    {
        $x = new BN($x, $enc);
        $y = new BN($y, $enc);

        // overflow
        if ($x->cmp($this->ec->p) >= 0 || $y->cmp($this->ec->p) >= 0) {
            return null;
        }

        $x = $x->toRed($this->ec->red);
        $y = $y->toRed($this->ec->red);

        // is odd flag
        if (($first === '06' || $first === '07') && $y->isOdd() !== ($first === '07')) {
            return null;
        }

        // x*x*x + b = y*y
        $x3 = $x->redSqr()->redIMul($x);
        if (!$y->redSqr()->redISub($x3->redIAdd($this->ec->b))->isZero()) {
            return null;
        }

        //return
    }

    protected function loadCompressedPublicKey(string $first, string $x, string $enc)
    {
        $x = new BN($x, $enc);

        // overflow
        if ($x->cmp($this->ec->p) >= 0) {
            return null;
        }
        $x = $x->toRed($this->ec->red);

        // compute corresponding Y
        $y = $x->redSqr()->redIMul($x)->redIAdd($this->ec->b)->redSqrt();
        if (($first === '03') !== $y->isOdd()) {
            $y = $y->redNeg();
        }

        //return
    }
    */
}
