<?php
namespace letnn;

class Crypt {
	public static function Encode($payload, $key = "", $algo = 'HS256') {
		$header = array('typ' => 'Jwt', 'alg' => $algo);
		$segments = array(
		            self::urlsafeB64Encode(json_encode($header)),
		            self::urlsafeB64Encode(json_encode($payload))
		        );
		$signing_input = implode('.', $segments);
		$signature = self::sign($signing_input, $key, $algo);
		$segments[] = self::urlsafeB64Encode($signature);
		return implode('.', $segments);
	}
	public static function Decode($Jwt, $key = "", $algo = "HS256") {
		$tks = explode('.', $Jwt);
		if (count($tks) != 3) {
			return false;
			die;
		}
		list($headb64, $payloadb64, $cryptob64) = $tks;
		if (null === ($header = json_decode(self::urlsafeB64Decode($headb64)))) {
			return false;
			die;
		}
		if (null === $payload = json_decode(self::urlsafeB64Decode($payloadb64))) {
			return false;
			die;
		}
		$sig = self::urlsafeB64Decode($cryptob64);
		if (isset($key)) {
			if (empty($header->alg)) {
				return false;
				die;
			}
			if (!self::verifySignature($sig, "$headb64.$payloadb64", $key, $algo)) {
				return false;
				die;
			}
		}
		return self::object_array($payload);
	}
	private static function object_array($array) {
		if(is_object($array)) {
			$array = (array)$array;
		}
		if(is_array($array)) {
			        foreach($array as $key=>$value) {
				$array[$key] = self::object_array($value);
			}
		}
		return $array;
	}
	private static function verifySignature($signature, $input, $key, $algo) {
		switch ($algo) {
			case'HS256':
			            case'HS384':
			            case'HS512':
			                return self::sign($input, $key, $algo) === $signature;
			case 'RS256':
			                return (boolean) openssl_verify($input, $signature, $key, OPENSSL_ALGO_SHA256);
			case 'RS384':
			                return (boolean) openssl_verify($input, $signature, $key, OPENSSL_ALGO_SHA384);
			case 'RS512':
			                return (boolean) openssl_verify($input, $signature, $key, OPENSSL_ALGO_SHA512);
			default:
			                return false;
			die;
		}
	}
	private static function sign($input, $key, $algo) {
		switch ($algo) {
			case 'HS256':
			                return hash_hmac('sha256', $input, $key, true);
			case 'HS384':
			                return hash_hmac('sha384', $input, $key, true);
			case 'HS512':
			                return hash_hmac('sha512', $input, $key, true);
			case 'RS256':
			                return self::generateRSASignature($input, $key, OPENSSL_ALGO_SHA256);
			case 'RS384':
			                return self::generateRSASignature($input, $key, OPENSSL_ALGO_SHA384);
			case 'RS512':
			                return self::generateRSASignature($input, $key, OPENSSL_ALGO_SHA512);
			default:
			                return false;
			die;
		}
	}
	private static function generateRSASignature($input, $key, $algo) {
		if (!openssl_sign($input, $signature, $key, $algo)) {
			return false;
			die;
		}
		return $signature;
	}
	private static function urlSafeB64Encode($data) {
		$b64 = base64_encode($data);
		$b64 = str_replace(array('+', '/', '\r', '\n', '='),
		                array('-', '_'),
		                $b64);
		return $b64;
	}
	private static function urlSafeB64Decode($b64) {
		$b64 = str_replace(array('-', '_'),
		                array('+', '/'),
		                $b64);
		return base64_decode($b64);
	}
}