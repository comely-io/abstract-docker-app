<?php
declare(strict_types=1);

namespace App\Common;

use App\Common\Exception\AppException;
use Comely\Security\Passwords;
use Comely\Utils\UTF8\UTF8Charset;
use Comely\Utils\Validator\ASCII_Validator;
use Comely\Utils\Validator\StringValidator;
use Comely\Utils\Validator\UTF8_Validator;

/**
 * Class Validator
 * @package App\Common
 */
class Validator
{
    /**
     * @param int $minLen
     * @param int $maxLen
     * @return UTF8_Validator
     */
    public static function UTF8(int $minLen = 2, int $maxLen = 64): UTF8_Validator
    {
        return \Comely\Utils\Validator\Validator::UTF8()->trim()
            ->cleanSpaces()
            ->len(min: $minLen, max: $maxLen)
            ->addCharset(UTF8Charset::Arabic)
            ->addCharset(UTF8Charset::Russian)
            ->addCharset(UTF8Charset::Hebrew)
            ->addCharset(UTF8Charset::Thai)
            ->utf8Options(allowASCII: true, allowSpaces: true, filterOutIllegals: false);
    }

    /**
     * @param int $maxLength
     * @param bool $allowDashes
     * @return StringValidator
     */
    public static function Name(int $maxLength = 16, bool $allowDashes = false): StringValidator
    {
        $matchExp = $allowDashes ? '/^[a-z\-\_\.]+(\s[a-z\-\_\.]+)*$/i' : '/^[a-z]+(\s[a-z]+)*$/i';
        return \Comely\Utils\Validator\Validator::String()->trim()->lowerCase()
            ->cleanSpaces()
            ->len(min: 3, max: $maxLength)
            ->match($matchExp)
            ->setCustomFn(function (string $validated) {
                return ucfirst($validated);
            });
    }

    /**
     * @param int $maxLength
     * @return StringValidator
     */
    public static function EmailAddress(int $maxLength = 64): StringValidator
    {
        return \Comely\Utils\Validator\Validator::String()->trim()->lowerCase()
            ->cleanSpaces()
            ->len(min: 9, max: $maxLength)
            ->setCustomFn(function (string $addr) {
                return self::isValidEmailAddress($addr) ? $addr : false;
            });
    }

    /**
     * @param int $minLength
     * @param int $maxLength
     * @return StringValidator
     */
    public static function Username(int $minLength = 6, int $maxLength = 16): StringValidator
    {
        return \Comely\Utils\Validator\Validator::String()->trim()
            ->cleanSpaces()
            ->len(min: $minLength, max: $maxLength)
            ->match('/^[a-zA-Z0-9]+[a-zA-Z0-9\-\_]?[a-zA-Z0-9]+$/');
    }

    /**
     * @param int $minLen
     * @param int $maxLen
     * @param int $minStrength
     * @return ASCII_Validator
     */
    public static function Password(int $minLen = 8, int $maxLen = 32, int $minStrength = 4): ASCII_Validator
    {
        return \Comely\Utils\Validator\Validator::ASCII()->trim()
            ->cleanSpaces()
            ->len(min: $minLen, max: $maxLen)
            ->setCustomFn(function (string $password) use ($minStrength) {
                if (Passwords::Strength($password) >= $minStrength) {
                    return $password;
                }

                return false;
            });
    }

    /**
     * @param mixed $email
     * @return bool
     */
    public static function isValidEmailAddress(mixed $email): bool
    {
        if (!is_string($email) || !$email) {
            return false;
        }

        return (filter_var($email, FILTER_VALIDATE_EMAIL) && Validator::isASCII($email, "@-._"));
    }

    /**
     * @param mixed $value
     * @param string|null $allow
     * @param bool|null $spaces
     * @return bool
     */
    public static function isASCII(mixed $value, ?string $allow = null, ?bool $spaces = true): bool
    {
        if (!is_string($value)) {
            return false;
        }

        $allowed = $allow ? preg_quote($allow, "/") : "";
        $checkSpaces = $spaces ? '\s' : '';
        $match = '/^[\w' . $checkSpaces . $allowed . ']*$/';

        return (bool)preg_match($match, $value);
    }

    /**
     * @param mixed $phone
     * @return bool
     */
    public static function isValidPhone(mixed $phone): bool
    {
        return is_string($phone) && preg_match('/^\+\d{1,6}\.\d{4,16}$/', $phone);
    }

    /**
     * @param mixed $username
     * @return bool
     */
    public static function isValidUsername(mixed $username): bool
    {
        if (is_string($username) && preg_match('/^[a-zA-Z\d]+[a-zA-Z\d\-_]?[a-zA-Z\d]+$/', $username)) {
            $len = strlen($username);
            if ($len >= 6 && $len <= 16) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param mixed $port
     * @param int $min
     * @return bool
     */
    public static function isValidPort(mixed $port, int $min = 0x03e8): bool
    {
        return is_int($port) && $port >= $min && $port <= 0xffff;
    }

    /**
     * @param mixed $hostname
     * @param bool $allowIpAddr
     * @return bool
     */
    public static function isValidHostname(mixed $hostname, bool $allowIpAddr = true): bool
    {
        if (!is_string($hostname) || !$hostname) {
            return false;
        }

        $hostname = strtolower($hostname);
        if (preg_match('/^[a-z\d\-]+(\.[a-z\d\-]+)*$/', $hostname)) {
            return true; // Validated as Domain
        }

        if ($allowIpAddr) {
            return (bool)filter_var($hostname, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6);
        }

        return false;
    }

    /**
     * @param $ip
     * @param bool $allowIPv6
     * @return bool
     */
    public static function isValidIP($ip, bool $allowIPv6 = true): bool
    {
        if (!is_string($ip) || !$ip) {
            return false;
        }

        return (bool)filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            $allowIPv6 ? FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6 : FILTER_FLAG_IPV4
        );
    }

    /**
     * @param mixed $val
     * @return bool
     */
    public static function getBool(mixed $val): bool
    {
        if (is_bool($val)) {
            return $val;
        }

        if ($val === 1) {
            return true;
        }

        if (is_string($val) && in_array(strtolower($val), ["1", "true", "on", "yes"])) {
            return true;
        }

        return false;
    }

    /**
     * @param mixed $val
     * @return string
     */
    public static function getType(mixed $val): string
    {
        return is_object($val) ? get_class($val) : gettype($val);
    }

    /**
     * @param mixed $val
     * @return bool
     */
    public static function isValidUserAgent(mixed $val): bool
    {
        if (!is_string($val) || !$val) {
            return false;
        }

        return (bool)preg_match('/^[\w\-]+\/([0-9]+(\.[0-9]+)?)\s\(.*\)?$/i', $val);
    }

    /**
     * @param object $obj
     * @return array
     * @throws \JsonException
     */
    public static function JSON_Filter(object $obj): array
    {
        return json_decode(
            json_encode($obj, JSON_THROW_ON_ERROR),
            true,
            flags: JSON_THROW_ON_ERROR
        );
    }
}
