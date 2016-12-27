<?php

use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Primitives\Point;
use Mdanter\Ecc\Primitives\PointInterface;
use Mdanter\Ecc\Random\RandomGeneratorFactory;
use Mdanter\Ecc\Serializer\Point\CompressedPointSerializer;
use Mdanter\Ecc\Serializer\Util\CurveOidMapper;
use Mdanter\Ecc\Serializer\PrivateKey\PemPrivateKeySerializer;
use Mdanter\Ecc\Serializer\PrivateKey\DerPrivateKeySerializer;
use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use Mdanter\Ecc\Serializer\PublicKey\PemPublicKeySerializer;
use Contracts\DecryptException;
use Contracts\EncryptException;
use Contracts\Encrypter as EncrypterContract;


/*
 *
 * Partial implementation of ECIES key encapsulation (ElGamal)
 * ISO 18033-2 10.2
 * http://www.shoup.net/iso/std6.pdf
 *
 * No OldCofactorMode, CofactorMode or CheckMode currently supported
 *
 */

class ECIESEncrypter implements EncrypterContract
{
    /**
     * The encryption key string in PEM format.
     *
     * @var string
     */
    protected $public_key;

    /**
     * The decryption key string in PEM format.
     *
     * @var string
     */
    protected $private_key;

    /**
     * Config for ECIES modes
     *
     * @var string
     */
    protected $single_hash_mode = true;

    /**
     * Length (in bytes) of the prime field for the chosen curve.
     * All calculated values are less than this so can be padded up to this length
     *
     * @var int
     */
    protected $prime_length;

    protected $adapter;
    protected $compressed_point_serializer;
    protected $random_number_generator;

    /**
     * The ephemeral public point
     *
     * @var Point
     */
    protected $gTilde;

    /**
     * The point of the ephemeral shared secret
     *
     * @var Point
     */
    protected $hTilde;

    /**
     * The octet string serialization of the ephemeral shared secret (without leading point-format byte)
     *
     * @var string
     */
    protected $PEH;

    /**
     * The generator point for the chosen curve
     *
     * @var Point
     */
    protected $generator_point;


    /**
     * The the serialized compressed ephemeral public point. Raw byte string, not hex.
     *
     * @var string
     */
    protected $ephemeral_public_point_serialized;


    /**
     * The symmetric encryption key derived from the ephemeral shared secret
     *
     * @var string
     */
    protected $derived_symmetric_key;

    /**
     * The symmetric MAC key derived from the ephemeral shared secret
     *
     * @var string
     */
    protected $derived_mac_key;

    /**
     * Either 'iso18033-2' or 'json'.
     * 'iso18033-2' should be compatible with other implementations of ECIES
     *
     * @var string
     */
    protected $output_structure;

    /**
     * Either 1 or 2.
     * Determines whether to implement KDF1 or KDF2 from ISO-18033-2
     *
     * @var int
     */
    protected $kdf_one_or_two = 2;

    /**
     * The length of the KDF generated hash (in bytes). Must ensure there are enough bytes for
     * both the chosen symmetric cipher and MAC key (in our case, 256 bits for each)
     *
     * @var int
     */
    protected $desired_hash_length = 64;

    /**
     * Must be a valid hashing algorithm
     *
     * @var string
     */
    protected $hash_algorithm = 'sha512';

    const PERMITTED_CURVES = [
        'secp112r1',
        'secp256k1',
        'secp256r1',
        'secp384r1',
        'nistp192',
        'nistp224',
        'nistp256',
        'nistp384',
        'nistp521'
    ];

    const ISO_FORMAT = 'iso18033-2';

    const JSON_FORMAT = 'json';

    /**
     * Create a new ECIESEncrypter instance.
     *
     * @param  string  $public_key
     * @param  string  $private_key
     * @param  string  $output_structure
     *
     * @throws \RuntimeException
     */

    public function __construct($public_key, $private_key, $output_structure = self::ISO_FORMAT)
    {
        if(is_null($public_key) && is_null($private_key)){
            throw new RuntimeException('Either public key or private key must be set in env(\'ECC_PUBLIC_KEY_PATH\') and env(\'ECC_PRIVATE_KEY_PATH\'). Could not locate either key');
        }

        if($output_structure != self::ISO_FORMAT && $output_structure != self::JSON_FORMAT){
            throw new RuntimeException('Output structure must be either "' . self::ISO_FORMAT . '" or "' . self::JSON_FORMAT . '"');
        }

        $this->output_structure = $output_structure;

        $pemPrivateKeySerializer = new PemPrivateKeySerializer(new DerPrivateKeySerializer());
        $pemPublicKeySerializer = new PemPublicKeySerializer(new DerPublicKeySerializer());


        if(!is_null($public_key)){
            $this->public_key = $pemPublicKeySerializer->parse($public_key);
            $curve = $this->public_key->getCurve();
        }

        if(!is_null($private_key)){
            $this->private_key = $pemPrivateKeySerializer->parse($private_key);
            $curve = $this->private_key->getCurve();
        }

        if(!is_null($curve) && !in_array($curve->getName(), self::PERMITTED_CURVES)){
            throw new RuntimeException('The only supported curves are secp112r1, secp256k1, secp256r1, secp384r1, nistp192, nistp224, nistp256, nistp384 and nistp521.');
        }

        $this->adapter = EccFactory::getAdapter();
        $this->compressed_point_serializer = new CompressedPointSerializer($this->adapter);
        $this->setGeneratorForCurve($curve->getName());
        $this->random_number_generator = RandomGeneratorFactory::getRandomGenerator();
        $this->prime_length =  CurveOidMapper::getByteSize($this->generator_point->getCurve());
    }

    /**
     * Sets the correct generator point for the curve used in the public or private key
     *
     * @param  string  $curve
     */
    protected function setGeneratorForCurve(string $curve = 'nistp521')
    {
        switch($curve){
            case 'secp112r1':
                $this->generator_point = EccFactory::getSecgCurves()->generator112r1();
                break;
            case 'secp256k1':
                $this->generator_point = EccFactory::getSecgCurves()->generator256k1();
                break;
            case 'secp256r1':
                $this->generator_point = EccFactory::getSecgCurves()->generator256r1();
                break;
            case 'secp384r1':
                $this->generator_point = EccFactory::getSecgCurves()->generator384r1();
                break;
            case 'nistp192':
                $this->generator_point = EccFactory::getNistCurves()->generator192();
                break;
            case 'nistp224':
                $this->generator_point = EccFactory::getNistCurves()->generator224();
                break;
            case 'nistp256':
                $this->generator_point = EccFactory::getNistCurves()->generator256();
                break;
            case 'nistp384':
                $this->generator_point = EccFactory::getNistCurves()->generator384();
                break;
            case 'nistp521':
                $this->generator_point = EccFactory::getNistCurves()->generator521();
                break;
            default:
                throw new RuntimeException('The only supported curves are secp112r1, secp256k1, secp256r1, secp384r1, nistp192, nistp224, nistp256, nistp384 and nistp521.');
        }
    }


    /**
     * This corresponds to ISO18033-2 - I2OSP(integer, octet_string_length)
     *
     * Converts 32-bit integer to BigEndian byte string
     * Primarily used for compatibility with Java BouncyCastle
     *
     * @param  int $i
     * @param int $length
     * @return string
     */
    public static function integerToOctetString($i, $length = 4)
    {
        if($i > PHP_INT_MAX){
            throw new RuntimeException("Integer larger than maximum allowed");
        }

        $length_in_bytes =  ceil(strlen(dechex($i)) / 2);

        if ($length_in_bytes > $length) {
            throw new RuntimeException("Integer cannot be stored in byte string of this length");
        }

        $length = $length * 2;
        return hex2bin(sprintf("%0".$length."X", $i));
    }

    /**
     * This corresponds to ISO18033-2 - HC.Encrypt(public_key, label, plaintext, options)
     *
     * @param $value
     * @param $label
     * @param $single_hash_mode
     *
     * @return string
     */
    public function encrypt($value, string $label = '', bool $single_hash_mode = true)
    {
        $this->single_hash_mode = $single_hash_mode;

        // random integer between 1 and the order (mu), acts as ephemeral private key
        $r =  $this->random_number_generator->generate($this->generator_point->getOrder());

        $this->generateEphemeralKeys($r);

        $C0 = $this->ephemeral_public_point_serialized;
        $C1 =  $this->encryptSymmetric($value, $label);

        $payload = $C1;

        if($this->output_structure === self::ISO_FORMAT){
            return base64_encode($C0 . $C1);
        }
        else{
            $payload['ephemeral_public_point'] = $C0;

            foreach ($payload as $key => $value){
                $payload[$key] = base64_encode($value);
            }

            $payload['label'] = $label;

            $json = json_encode($payload);

            if (! is_string($json)) {
                throw new EncryptException('Could not encrypt the data.');
            }
            return $json;
        }
    }


    /**
     * This corresponds to ISO18033-2 - KEM.Encrypt(public_key, options)
     * No OldCofactorMode, CofactorMode or CheckMode currently supported
     * @param \GMP $r
     * @return string
     */
    protected function generateEphemeralKeys(\GMP $r)
    {
        if(is_null($this->public_key)){
            throw new EncryptException('Could not encrypt without the public key');
        }
        // If you're unfamiliar with ECIES, it might be helpful to think of ECIES as similar to Elliptic Curve Diffie-Hellman key exchange, only using an ephemeral private key ($r) to derive an ephemeral public point ($gTilde), which is then sent with the ciphertext and used on the other side to reconstruct the shared secret.

        // $h is the permanent public point, which is the x (the permanent private key) times the generator
        // i.e. $h = $this->generator_point->mul($private_key)
        $h = $this->public_key->getPoint();


        // no OldCofactorMode at the moment, otherwise we'd multiply $r by nu (where nu = (the index of G in H) modulo mu)
        $rPrime = $r;

        // gTilde is the ephemeral public point. This means a new point which can be used to reconstruct $r
        // (iff you have the permanent private key)
        $this->gTilde = $this->generator_point->mul($r);


        /*
         hTilde is the point of the ephemeral shared secret.
         It can be calculated as either :
                  (permanent_private * generator) * ephemeral_private
          i.e.    (       permanent_public      ) * ephemeral_private   // when encrypting
            OR
                  (ephemeral_private * generator) * permanent_private
         i.e.     (       ephemeral_public      ) * permanent_private   // when decrypting
        */
        $this->hTilde = $h->mul($rPrime);

        return $this->deriveKeysFromEphemeralPoints();
    }


    /**
     * This corresponds to ISO18033-2 - DEM.Encrypt(symmetric_key, label, message)
     *
     * @param $value
     * @param $label
     *
     * @return string
     */
    protected function encryptSymmetric($value, $label)
    {
        $iv = random_bytes(16); // 16 byte IV because block size is 128-bit, even with 256 bit key

        $ciphertext = \openssl_encrypt(igbinary_serialize($value), 'AES-256-CBC', $this->derived_symmetric_key, 0, $iv);

        if ($ciphertext === false) {
            throw new EncryptException('Could not encrypt the data.');
        }

        $ciphertext = base64_decode($ciphertext);

        $mac = hash_hmac('sha256', $iv . $ciphertext . $label . $this->integerToOctetString(8 * strlen($label), 8), $this->derived_mac_key, true);

        $C1 =  $iv . $ciphertext . $mac;

        if($this->output_structure === self::ISO_FORMAT){
            return $C1;
        }

        return compact('iv', 'ciphertext', 'mac');
    }


    /**
     * This corresponds to ISO18033-2 - HC.Decrypt(private_key, label, ciphertext)
     *
     * @param $payload
     * @param $label
     * @param $single_hash_mode
     *
     * @return string
     */
    public function decrypt($payload, $label = '', $single_hash_mode = true)
    {
        $this->single_hash_mode = $single_hash_mode;

        if($this->output_structure === self::ISO_FORMAT){
            $payload = base64_decode($payload);
            $C0 = substr($payload, 0, $this->prime_length + 1);
            $C1 = substr($payload, $this->prime_length + 1);

            if(strlen($C1) < strlen($this->derived_mac_key) + 16 + 16 ){ // IV length is 128-bits (16 bytes), minimum block is 128-bits, MAC key is whatever
                throw new DecryptException('Could not decrypt. Payload too short');
            }

            $iv = substr($C1, 0, 16);

            $ciphertext = substr($C1, 16, strlen($C1) - 32 - 16); // minus 32 bytes for mac_code, minus 16 for IV.

            $mac = substr($C1, -32); // last 32 bytes is SHA-256 MAC code

        }
        else{

            $payload = \GuzzleHttp\json_decode($payload, JSON_OBJECT_AS_ARRAY);

            $C0 = base64_decode($payload['ephemeral_public_point']);

            $iv = base64_decode($payload['iv']);

            $ciphertext = base64_decode($payload['ciphertext']);

            $mac = base64_decode($payload['mac']);

            $label = $payload['label'];

        }

        $this->reconstructSharedSecret($C0);

        $decrypted = $this->decryptSymmetric($iv, $ciphertext, $mac, $label);

        return igbinary_unserialize($decrypted);
    }


    /**
     * This corresponds to KEM.Decrypt(private_key, ephemeral_public_point)
     *
     * @param $C0
     * The ephemeral public point
     */
    protected function reconstructSharedSecret(string $C0){
        if(is_null($this->private_key)){
            throw new DecryptException('Could not decrypt without the private key');
        }

        $this->gTilde = $this->compressed_point_serializer->unserialize($this->generator_point->getCurve(), bin2hex($C0));

        $this->hTilde = $this->gTilde->mul($this->private_key->getSecret());

        if($this->hTilde->isInfinity()){
            throw new DecryptException('Ephemeral shared secret was infinity');
        }

        $this->deriveKeysFromEphemeralPoints();
    }


    /**
     * This derives the symmetric key and MAC key from the serialized ephemeral shared secret ($hTilde)
     *
     * @param PointInterface $hTilde
     * @param PointInterface $gTilde
     *
     * @return string
     */
    protected function deriveKeysFromEphemeralPoints()
    {

        // C0 is the octet string encoded version of the ephemeral public point (gTilde)
        $C0 = hex2bin($this->compressed_point_serializer->serialize($this->gTilde));

        // PEH is the octet encoded shared secret point, used in the KDF to derive symmetric key
        // We remove the leading "point-format" byte because PEH is generated by the partial encoding function E'()
        $this->PEH = ltrim(hex2bin($this->compressed_point_serializer->serialize($this->hTilde)), hex2bin($this->compressed_point_serializer->getPrefix($this->hTilde)));

        if($this->single_hash_mode){
            // SHA-512 hash of binary $PEH,
            // BigEndian 32-bit '1' appended to match Java BouncyCastle KDF2BytesGenerator implementation of ISO18033-2 KDF2
            // where k = desired_length/hash_length = 64/64 = 1
            $kdf_bytes = $this->KDF($this->PEH);
        }
        else{
            // SHA-512 hash of binary $C || binary $PEH
            // BigEndian 32-bit '1' appended to match Java BouncyCastle KDF2BytesGenerator implementation of ISO18033-2 KDF2
            // where k = desired_length/hash_length = 64/64 = 1
            $kdf_bytes = $this->KDF($C0 . $this->PEH);
        }

        // 32 byte (256 bit) AES key derived from SHA-512 hash of shared secret point
        $kdf_symmetric_key = substr($kdf_bytes, 0, 32);

        // 32 byte (256 bit) HMAC key derived from SHA-512 hash of shared secret point
        $kdf_mac_key = substr($kdf_bytes, 32, 32);

        $this->ephemeral_public_point_serialized = $C0;
        $this->derived_symmetric_key = $kdf_symmetric_key;
        $this->derived_mac_key = $kdf_mac_key ;

        return $kdf_bytes;
    }


    /**
     * Corresponds to ISO18033-2 - KDF(x, length), where length = 512 bits (64 bytes) and therefore k=1
     * Can be switched between KDF1 and KDF2
     *
     * @param string $input
     * @return string
     * @internal param $one_or_two
     * @internal param int $desired_hash_length
     * @internal param string $hash_algorithm
     */
    protected function KDF(string $input)
    {
        $permitted_algorithms = hash_algos();

        if(!in_array($this->hash_algorithm, $permitted_algorithms)){
            throw new InvalidArgumentException("Hash algorithm '". $this->hash_algorithm . "' does not exist");
        }

        $hash_length = strlen(hash($this->hash_algorithm, 'anything', true));

        $k = ceil($this->desired_hash_length/$hash_length);

        if($this->kdf_one_or_two == 1){
            $start = 0;
            $end = $k - 1;
        }
        else{
            $start = 1;
            $end = $k;
        }

        $kdf_bytes = '';
        for($i = $start; $i <= $end; $i++){
            $kdf_bytes .= hash($this->hash_algorithm, $input . $this->integerToOctetString($i, 4), true);
        }
        return substr($kdf_bytes, 0, $this->desired_hash_length);

    }


    /**
     * Corresponds to ISO18033-2 - KDF1(x, length), where length = 512 bits (64 bytes) and therefore k=1
     *
     * @param string $input
     * @param int $desired_hash_length
     *
     * @param string $hash_algorithm
     * @return string
     */
    protected function KDF1(string $input, int $desired_hash_length = 64, $hash_algorithm = 'sha512')
    {
        $this->kdf_one_or_two = 1;
        $this->desired_hash_length = $desired_hash_length;
        $this->hash_algorithm = $hash_algorithm;
        return $this->KDF($input);
    }


    /**
     * Corresponds to ISO18033-2 - KDF2(x, length), where length = 512 bits (64 bytes) and therefore k=1
     *
     * @param string $input
     * @param int $desired_hash_length
     *
     * @param string $hash_algorithm
     * @return string
     */
    protected function KDF2(string $input, int $desired_hash_length = 64, $hash_algorithm = 'sha512')
    {
        $this->kdf_one_or_two = 2;
        $this->desired_hash_length = $desired_hash_length;
        $this->hash_algorithm = $hash_algorithm;
        return $this->KDF($input);
    }

    /**
     * This corresponds to DEM.Decrypt(symmetric_key, label, ciphertext)
     *
     * @param $iv
     * @param $ciphertext
     * @param $mac
     * @param $label
     *
     * @return string
     */
    protected function decryptSymmetric($iv, $ciphertext, $mac, $label)
    {
        $calculated_mac = hash_hmac('sha256', $iv . $ciphertext . $label . $this->integerToOctetString(8 * strlen($label), 8), $this->derived_mac_key, true);

        if(! hash_equals($calculated_mac, $mac)){
            throw new DecryptException('The MAC is invalid.');
        }

        $decrypted = \openssl_decrypt(base64_encode($ciphertext), 'AES-256-CBC', $this->derived_symmetric_key, 0, $iv);

        if ($decrypted === false) {
            throw new DecryptException('Could not decrypt the data.');
        }

        return $decrypted;
    }


}