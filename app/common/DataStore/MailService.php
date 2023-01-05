<?php
declare(strict_types=1);

namespace App\Common\DataStore;

/**
 * Class MailService
 * @package App\Common\DataStore
 */
enum MailService: string
{
    case DISABLED = "disabled"; // Queue also disabled
    case PAUSED = "paused"; // E-mails will be queued
    case SMTP = "smtp";
    case MAILGUN = "mailgun";
}
