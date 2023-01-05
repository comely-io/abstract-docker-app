<?php
declare(strict_types=1);

namespace App\Common\Misc;

use App\Common\Database\AbstractAppModel;
use App\Common\Database\Primary\MailsQueue;

/**
 * Class QueuedMail
 * @package App\Common\Misc
 */
class QueuedMail extends AbstractAppModel
{
    public const TABLE = MailsQueue::TABLE;
    public const SERIALIZABLE = false;

    /** @var int */
    public int $id;
    /** @var string */
    public string $status;
    /** @var string */
    public string $email;
    /** @var string */
    public string $subject;
    /** @var int */
    public int $addedOn;
    /** @var int */
    public int $attempts = 0;
    /** @var int|null */
    public ?int $lastAttempt = null;
    /** @var int|null */
    public ?int $sentOn = null;
    /** @var string|null */
    public ?string $error = null;
}
