<?php
declare(strict_types=1);

namespace App\Common\DataStore;

/**
 * Class MailConfig
 * @package App\Common\DataStore
 */
class MailConfig extends AbstractDataStoreObject
{
    public const DB_KEY = "app.mailConfig";
    public const CACHE_KEY = "app.mailConfig";
    public const CACHE_TTL = 86400 * 7;
    public const IS_ENCRYPTED = true;

    /** @var MailService */
    public MailService $service = MailService::DISABLED;
    /** @var string */
    public string $senderName;
    /** @var string */
    public string $senderEmail;
    /** @var int */
    public int $timeOut = 1;
    /** @var bool */
    public bool $useTLS = true;
    /** @var null|string */
    public ?string $hostname = null;
    /** @var int */
    public int $port = 587;
    /** @var null|string */
    public ?string $username = null;
    /** @var null|string */
    public ?string $password = null;
    /** @var null|string */
    public ?string $serverName = null;
    /** @var string|null */
    public ?string $mgApiKey = null;
    /** @var string|null */
    public ?string $mgApiDomain = null;
    /** @var bool|null */
    public ?bool $mgEurope = null;
}
