<?php
declare(strict_types=1);

namespace App\Common\Kernel\Config;

use App\Common\Exception\AppConfigException;
use Comely\Utils\OOP\Traits\NoDumpTrait;
use Comely\Utils\Validator\Exception\ValidatorException;
use Comely\Utils\Validator\Validator;

/**
 * Class EnvConfig
 * @package App\Common\Kernel\Config
 */
class EnvConfig
{
    /** @var string */
    public readonly string $timeZone;
    /** @var string */
    public readonly string $adminHost;
    /** @var int */
    public readonly int $adminPort;
    /** @var string */
    public readonly string $publicHost;
    /** @var int */
    public readonly int $publicPort;
    /** @var string|null */
    public readonly ?string $mysqlRootPassword;
    /** @var int */
    public readonly int $phpMyAdminPort;

    use NoDumpTrait;

    /**
     * @throws AppConfigException
     */
    public function __construct()
    {
        // Timezone
        $tz = $this->getEnv("APP_TIMEZONE");
        if (!$tz || !in_array($tz, \DateTimeZone::listIdentifiers())) {
            throw new AppConfigException('Env[APP_TIMEZONE]: Invalid timezone');
        }

        $this->timeZone = $tz;

        // Validators
        $hostnameValidator = Validator::ASCII()->setCustomFn(function (string $hostname) {
            return \App\Common\Validator::isValidHostname($hostname, allowIpAddr: false) ? $hostname : false;
        });

        $portValidator = Validator::Integer()->range(80, 0xffff);

        // Admin API Server/Hostname & Port
        try {
            $this->adminHost = $hostnameValidator->getValidated($this->getEnv("ADMIN_HOST"));
        } catch (ValidatorException $e) {
            throw new AppConfigException(sprintf('Env[ADMIN_HOST]: Invalid domain name (0x%s)', dechex($e->getCode())));
        }

        try {
            $this->adminPort = $portValidator->getValidated($this->getEnv("ADMIN_PORT"));
        } catch (ValidatorException $e) {
            throw new AppConfigException(sprintf('Env[ADMIN_PORT]: Invalid port (0x%s)', dechex($e->getCode())));
        }

        // Public API Server/Hostname & Port
        try {
            $this->publicHost = $hostnameValidator->getValidated($this->getEnv("PUBLIC_HOST"));
        } catch (ValidatorException $e) {
            throw new AppConfigException(sprintf('Env[PUBLIC_HOST]: Invalid domain name (0x%s)', dechex($e->getCode())));
        }

        try {
            $this->publicPort = $portValidator->getValidated($this->getEnv("PUBLIC_PORT"));
        } catch (ValidatorException $e) {
            throw new AppConfigException(sprintf('Env[PUBLIC_PORT]: Invalid port (0x%s)', dechex($e->getCode())));
        }

        // MySQL Root Password
        try {
            $this->mysqlRootPassword = Validator::ASCII()->match('/^[a-z0-9@#~_\-.$^&*()!]{4,32}$/i')
                ->getNullable($this->getEnv("MYSQL_ROOT_PASSWORD"), emptyStrIsNull: true);
        } catch (ValidatorException $e) {
            throw new AppConfigException(sprintf('Env[MYSQL_ROOT_PASSWORD]: Invalid MySQL root password (0x%s)', dechex($e->getCode())));
        }

        // PhpMyAdmin Port
        try {
            $this->phpMyAdminPort = $portValidator->getValidated($this->getEnv("PMA_LISTEN"));
        } catch (ValidatorException $e) {
            throw new AppConfigException(sprintf('Env[PMA_LISTEN]: Invalid port (0x%s)', dechex($e->getCode())));
        }
    }

    /**
     * @param string $key
     * @return string
     */
    private function getEnv(string $key): string
    {
        return trim(strval(getenv($key)));
    }
}
