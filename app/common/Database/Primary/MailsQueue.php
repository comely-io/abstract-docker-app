<?php
declare(strict_types=1);

namespace App\Common\Database\Primary;

use App\Common\Database\AbstractAppTable;
use Comely\Database\Schema\Table\Columns;
use Comely\Database\Schema\Table\Constraints;

/**
 * Class MailsQueue
 * @package App\Common\Database\Primary
 */
class MailsQueue extends AbstractAppTable
{
    public const TABLE = "mails_queue";
    public const ORM_CLASS = 'App\Common\Misc\QueuedMail';

    /**
     * @param \Comely\Database\Schema\Table\Columns $cols
     * @param \Comely\Database\Schema\Table\Constraints $constraints
     * @return void
     */
    public function structure(Columns $cols, Constraints $constraints): void
    {
        $cols->int("id")->bytes(4)->unSigned()->autoIncrement();
        $cols->enum("status")->options("sent", "queued", "exhausted");
        $cols->string("email")->length(80);
        $cols->string("subject")->length(128);
        $cols->binary("blob")->length(5242880)->nullable(); // Up to 5MiB
        $cols->int("added_on")->bytes(4)->unSigned();
        $cols->int("attempts")->bytes(1)->unSigned()->default(0);
        $cols->int("last_attempt")->bytes(4)->unSigned()->nullable();
        $cols->int("sent_on")->bytes(4)->unSigned()->nullable();
        $cols->string("error")->length(255)->nullable();
        $cols->primaryKey("id");
    }
}
