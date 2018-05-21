# BIP-44 in PHP

## About

This is a pure PHP SDK for working with BIP-44 standart

## Installing

```bash
composer require minter/minter-php-bip-44
```

## Using SDK

### Get private key by path

Returns a string

###### Example

* Get private key by path and seed

```php
use BIP\BIP44;

$seed = 'a95e6ca6908e9d6051479c0083e62d2dd3067878091455d52fef322032bf888ebaa6482a343b8c6b2e6d051c3a1701228358d27af550e65a858ce612c4713933';

$HDKey = BIP44::fromMasterSeed($seed)->derive("m/44'/60'/0'/0/0");

echo $HDKey->privateKey; // 2e1c993e0b05e1facc80d405fba18c9fa263d89e4caffe342417c40c7c46742f
```

* Get extended keys by path and seed

```php
use BIP\BIP44;

$seed = 'a95e6ca6908e9d6051479c0083e62d2dd3067878091455d52fef322032bf888ebaa6482a343b8c6b2e6d051c3a1701228358d27af550e65a858ce612c4713933';

$HDKey = BIP44::fromMasterSeed($seed)->derive("m/44'/60'/0'/0");

echo $HDKey->getPublicExtendedKey(); // xpub6Dnoiy4pCzyjYYan4SNvbnKH9pZNHvHKWrMGWD6RnZ7SC4RA57S1csNfYXbCywk27x4cGdwdYFr2cRwa3fGfG9nDV2z7B5njAFNshjzeA2n

echo $HDKey->getPrivateExtendedKey(); // xprv9zoTKTXvNdRSL4WJxQqvEeNYbnistTZU9dRfhpgpEDaTKG61Xa7m554BhEZdsQB8y5eK2k5XdZNoRQv9zFD7sN9hnuW28NdsYtC1J8kvsNe
```

## License

The BIP-44 PHP SDK is open-sourced software licensed under the [MIT license](https://opensource.org/licenses/MIT).
