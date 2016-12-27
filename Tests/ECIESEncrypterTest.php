<?php

namespace Tests;

use PHPUnit\Framework\TestCase;
use Contracts\DecryptException;
use Contracts\EncryptException;
use FG\ASN1\Exception\ParserException;
use Mdanter\Ecc\Crypto\Key\PrivateKey;
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Primitives\Point;
use ECIESEncrypter;

class ECIESEncrypterTest extends TestCase
{
    protected $encrypter;

    protected $plaintext = "The rain in spain falls just before the mountain ridge, but they wouldn't want you to know that, because it would spoil the rhyme";

    protected $ciphertext;

    // requires private_key1.pem to decrypt
    protected $original_iso_format_ciphertext = 'AgEiTo9QVuNIVuOMbd1/VvvItyAV+wUfGFzPJwkwblIR2sHsXER6Ec3NTYu4k+Reu1hANE3XG9JgPjbYOYk1H/9W1vekveEtNhsZTnzz/mm4+bGOCbHI0UPJ+a+up/SjrYvG09V8LgRsDOq3EikZbgyhsO+PPs7VMYCO2pkIsEgJtw8+XHLtjt8Xmbs1GdrIwLHIuU9cGrcpn5yuWNcinfqmdw7zfE1smocfs/YfS468NlMPeSddvkXfg9AyNDg9axsfa+YgmOPXZGiRNRWmI5Jmf12NaJaEI1hE2fmZ8fQCKRWv7qQqLp6Blyf8+bF7/Nl7QUQulYHkR2HJen6R6NtRKg==';

    // requires private_key1.pem to decrypt
    protected $original_json_format_ciphertext = '{"iv":"V1EeKumtqJKapR4mjkxz\/A==","ciphertext":"dpihDpnnyjdwUR9ZBQA3aiBv3a\/4yG9BioRcXvcwcg9L00oX82gbD062Y0\/KbKK4js7SZqjbeK2xPsGA5OzLPaxfiCZSyeuKrsCbRB2txsFVGAhAkzTUU7UwQmbsttpvEvwitPcvWzfL1UiPLisITFFKebPfUGC8Ehl1mOST8+HuYOyID199yDaRVefssmII","mac":"7D\/fkofzfb1XXFdocLo4CyS4HHXlu8XStZHEEH0hHMc=","ephemeral_public_point":"AgHr\/1fqq3E4MYIkq9z5JDfRrSBvpbOqYZChl8yrfJDc\/sm7uowG1aecvlebNaB8y8slhoqGPJKqc\/bbnZYOoVUikA==","label":"Spanish rain"}';

    protected static function getMethod($name)
    {
        $class = new \ReflectionClass('\\ECIESEncrypter');
        $method = $class->getMethod($name);
        $method->setAccessible(true);
        return $method;
    }

    protected static function getProperty($name)
    {
        $class = new \ReflectionClass('\\ECIESEncrypter');
        $property = $class->getProperty($name);
        $property->setAccessible(true);
        return $property;
    }

    public function testEncryptThenDecryptNoLabel()
    {
        $public_key = file_get_contents('keys/public_key1.pem');
        $private_key = file_get_contents('keys/private_key1.pem');
        $this->encrypter = new ECIESEncrypter($public_key, $private_key);

        $ciphertext = $this->encrypter->encrypt($this->plaintext);

        $decrypted = $this->encrypter->decrypt($ciphertext);

        $this->assertEquals($this->plaintext, $decrypted);
    }


    public function testEncryptThenDecryptNewEncrypterNoLabel()
    {
        $public_key = file_get_contents('keys/public_key1.pem');
        $private_key = file_get_contents('keys/private_key1.pem');
        $this->encrypter = new ECIESEncrypter($public_key, $private_key);

        $ciphertext = $this->encrypter->encrypt($this->plaintext);

        $this->encrypter = null;

        $this->encrypter = new ECIESEncrypter($public_key, $private_key);

        $decrypted = $this->encrypter->decrypt($ciphertext);

        $this->assertEquals($this->plaintext, $decrypted);
    }


    public function testEncryptThenDecryptWithCorrectLabel()
    {
        $public_key = file_get_contents('keys/public_key1.pem');
        $private_key = file_get_contents('keys/private_key1.pem');
        $this->encrypter = new ECIESEncrypter($public_key, $private_key);

        $ciphertext = $this->encrypter->encrypt($this->plaintext, 'Spanish rain');

        $decrypted = $this->encrypter->decrypt($ciphertext, 'Spanish rain');

        $this->assertEquals($this->plaintext, $decrypted);
    }

    public function testEncryptThenDecryptWithIncorrectLabel()
    {
        $public_key = file_get_contents('keys/public_key1.pem');
        $private_key = file_get_contents('keys/private_key1.pem');
        $this->encrypter = new ECIESEncrypter($public_key, $private_key);

        $this->expectException(DecryptException::class);

        $ciphertext = $this->encrypter->encrypt($this->plaintext, 'Spanish rain');

        $this->encrypter->decrypt($ciphertext, 'French rain');
    }

    public function testEncryptWithoutPublicKey()
    {
        $public_key = null;
        $private_key = file_get_contents('keys/private_key1.pem');
        $this->encrypter = new ECIESEncrypter($public_key, $private_key);

        $this->expectException(EncryptException::class);

        $this->encrypter->encrypt($this->plaintext);
    }

    public function testDecryptWithoutPrivateKey()
    {
        $public_key = file_get_contents('keys/public_key1.pem');
        $private_key = null;
        $this->encrypter = new ECIESEncrypter($public_key, $private_key);

        $this->expectException(DecryptException::class);

        $ciphertext = $this->encrypter->encrypt($this->plaintext);

        $this->encrypter->decrypt($ciphertext);
    }

    public function testEncryptThenDecryptWithIncorrectKey()
    {
        $public_key = file_get_contents('keys/public_key1.pem');
        $private_key = file_get_contents('keys/private_key2.pem');
        $this->encrypter = new ECIESEncrypter($public_key, $private_key);

        $this->expectException(DecryptException::class);

        $ciphertext = $this->encrypter->encrypt($this->plaintext);

        $this->encrypter->decrypt($ciphertext);
    }

    public function testEncryptWithInvalidPublicKey()
    {
        $public_key = file_get_contents('keys/invalid.pem');
        $private_key = file_get_contents('keys/private_key1.pem');

        $this->expectException(ParserException::class);

        $this->encrypter = new ECIESEncrypter($public_key, $private_key);
    }

    public function testDecryptWithInvalidPrivateKey()
    {
        $public_key = file_get_contents('keys/public_key1.pem');
        $private_key = file_get_contents('keys/invalid.pem');

        $this->expectException(ParserException::class);

        $this->encrypter = new ECIESEncrypter($public_key, $private_key);
    }

    public function testEncryptWithUnsupportedCurve()
    {
        $public_key = file_get_contents('keys/unsupported_public_key.pem');
        $private_key = null;

        $this->expectException(\RuntimeException::class);

        $this->encrypter = new ECIESEncrypter($public_key, $private_key);
    }

    public function testEncryptWithoutPrivateKey()
    {
        $public_key = file_get_contents('keys/public_key1.pem');
        $private_key = null;

        $this->encrypter = new ECIESEncrypter($public_key, $private_key);

        $ciphertext = $this->encrypter->encrypt($this->plaintext);

        $this->ciphertext = $ciphertext;

        $this->assertNotNull($ciphertext);
    }

    /**
     * @depends testEncryptWithoutPrivateKey
     */
    public function testDecryptWithoutPublicKey()
    {
        // set ciphertext property

        $this->testEncryptWithoutPrivateKey();

        $public_key = null;
        $private_key = file_get_contents('keys/private_key1.pem');
        $this->encrypter = new ECIESEncrypter($public_key, $private_key);

        $decrypted = $this->encrypter->decrypt($this->ciphertext);

        $this->assertEquals($this->plaintext, $decrypted);
    }


    public function testDecryptPreviousCiphertextISOFormat()
    {

        $public_key = file_get_contents('keys/public_key1.pem');
        $private_key = file_get_contents('keys/private_key1.pem');
        $this->encrypter = new ECIESEncrypter($public_key, $private_key, ECIESEncrypter::ISO_FORMAT);

        $decrypted = $this->encrypter->decrypt($this->original_iso_format_ciphertext);

        $this->assertEquals($this->plaintext, $decrypted);
    }


    public function testDecryptPreviousCiphertextJSONFormat()
    {

        $public_key = file_get_contents('keys/public_key1.pem');
        $private_key = file_get_contents('keys/private_key1.pem');
        $this->encrypter = new ECIESEncrypter($public_key, $private_key, ECIESEncrypter::JSON_FORMAT);

        $decrypted = $this->encrypter->decrypt($this->original_json_format_ciphertext, 'Spanish rain');

        $this->assertEquals($this->plaintext, $decrypted);
    }



    ########## HERE BE DRAGONS ###########

    /**
     * This is comparing the internal workings of the standard implementation with our implementation
     * The expected values are copied from Test Vector C.2.3 of the ISO 18033-2:2004 Final Committee Draft
     */

    public function testInternalValuesAgainstExpectedValues()
    {

        $public_key = file_get_contents('keys/nistp192_public_key.pem');
        $private_key = file_get_contents('keys/nistp192_private_key.pem');

        $this->encrypter = new ECIESEncrypter($public_key, $private_key);

        // expected value initialisation

        $adapter = EccFactory::getAdapter();
        $curve = EccFactory::getNistCurves()->curve192();
        $generator = EccFactory::getNistCurves()->generator192();

        $expected_gTilde = new Point($adapter, $curve, gmp_init('ccc9ea07b8b71d25646b22b0e251362a3fa9e993042315df', 16), gmp_init('047b2e07dd2ffb89359945f3d22ca8757874be2536e0f924', 16));
        $expected_hTilde = new Point($adapter, $curve, gmp_init('cdec12c4cf1cb733a2a691ad945e124535e5fc10c70203b5', 16), gmp_init('0cae66e42ae0dd8857ab670c6397c93c1769f9a5f5b9d36d', 16));
        $expected_C0 = hex2bin('02ccc9ea07b8b71d25646b22b0e251362a3fa9e993042315df');
        $expected_PEH = hex2bin('cdec12c4cf1cb733a2a691ad945e124535e5fc10c70203b5');
        $expected_derived_bytes = hex2bin('8fbe0903fac2fa05df02278fe162708fb432f3cbf9bb14138d22be1d279f74bfb94f0843a153b708fcc8d9446c76f00e4ccabef85228195f732f4aedc5e48efcf2968c3a46f2df6f2afcbdf5ef79c958f233c6d208f3a7496e08f505d1c792b314b45ff647237b0aa186d0cdbab47a00fb4065d62cfc18f8a8d12c78ecbee3fd');
        $expected_private_key = new PrivateKey($adapter, $generator, gmp_init('b67048c28d2d26a73f713d5ebb994ac92588464e7fe7d3f3', 16));

        $r =  gmp_init('083d4ac64f1960a9836a84f91ca211a185814fa43a2c8f21', 16);


        $internal_private_key = self::getProperty('private_key')->getValue($this->encrypter);
        $this->assertEquals($expected_private_key->getSecret(), $internal_private_key->getSecret());


        self::getProperty('single_hash_mode')->setValue($this->encrypter, false);
        self::getProperty('kdf_one_or_two')->setValue($this->encrypter, 1);
        self::getProperty('desired_hash_length')->setValue($this->encrypter, 128);
        self::getProperty('hash_algorithm')->setValue($this->encrypter, 'sha1');

        $derived_bytes = self::getMethod('generateEphemeralKeys')->invokeArgs($this->encrypter, array($r));
        $gTilde = self::getProperty('gTilde')->getValue($this->encrypter);
        $hTilde = self::getProperty('hTilde')->getValue($this->encrypter);
        $PEH = self::getProperty('PEH')->getValue($this->encrypter);
        $C0 = self::getProperty('ephemeral_public_point_serialized')->getValue($this->encrypter);

        $this->assertEquals($gTilde->getX(), $expected_gTilde->getX());
        $this->assertEquals($hTilde->getX(), $expected_hTilde->getX());
        $this->assertEquals($expected_C0, $C0);
        $this->assertEquals($expected_PEH, $PEH);
        $this->assertEquals($expected_derived_bytes, $derived_bytes);
    }


}
