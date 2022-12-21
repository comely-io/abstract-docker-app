<?php
declare(strict_types=1);

namespace App\Common\Users;

use App\Common\Database\AbstractAppModel;
use App\Common\Database\Primary\Users\Logs;

/**
 * Class Log
 * @package App\Common\Users
 */
class Log extends AbstractAppModel
{
    public const TABLE = Logs::TABLE;
    public const SERIALIZABLE = false;

    /** @var int */
    public int $id;
    /** @var int */
    public int $user;
    /** @var string|null|array */
    public null|string|array $flags;
    /** @var string|null */
    public ?string $controller;
    /** @var string */
    public string $log;
    /** @var string */
    public string $ipAddress;
    /** @var int */
    public int $timeStamp;
}
