<?php
declare(strict_types=1);

namespace App\Common\Database\Primary\Users;

use App\Common\AppKernel;
use App\Common\Database\AbstractAppTable;
use App\Common\Database\Primary\Users;
use App\Common\Exception\AppException;
use App\Common\Users\Log;
use App\Common\Users\User;
use Comely\Database\Schema\Table\Columns;
use Comely\Database\Schema\Table\Constraints;

/**
 * Class Logs
 * @package App\Common\Database\Primary\Users
 */
class Logs extends AbstractAppTable
{
    public const TABLE = "u_logs";
    public const ORM_CLASS = 'App\Common\Users\Log';

    /**
     * @param Columns $cols
     * @param Constraints $constraints
     * @return void
     */
    public function structure(Columns $cols, Constraints $constraints): void
    {
        $cols->defaults("ascii", "ascii_general_ci");

        $cols->int("id")->bytes(4)->unSigned()->autoIncrement();
        $cols->int("user")->bytes(4)->unSigned();
        $cols->string("flags")->length(255)->nullable();
        $cols->string("controller")->length(255)->nullable();
        $cols->string("log")->length(255);
        $cols->string("ip_address")->length(45);
        $cols->int("time_stamp")->bytes(4)->unSigned();
        $cols->primaryKey("id");

        $constraints->foreignKey("user")->table(Users::TABLE, "id");
    }

    /**
     * @param User $user
     * @param string $ipAddress
     * @param string $message
     * @param string|null $controller
     * @param int|null $line
     * @param array $flags
     * @return Log
     * @throws AppException
     * @throws \Comely\Database\Exception\DatabaseException
     */
    public static function Insert(
        User    $user,
        string  $ipAddress,
        string  $message,
        ?string $controller = null,
        ?int    $line = null,
        array   $flags = []
    ): Log
    {
        if (!preg_match('/^\w+[\w\s@\-:=+.#\",()\[\];]+$/', $message)) {
            throw new AppException('User log entry contains an illegal character');
        } elseif (strlen($message) > 255) {
            throw new AppException('User log entry cannot exceed 255 bytes');
        }

        $logFlags = null;
        if ($flags) {
            $logFlags = [];
            $flagIndex = -1;
            foreach ($flags as $flag) {
                $flagIndex++;
                if (!preg_match('/^[\w.\-]{1,16}(:\d{1,10})?$/', $flag)) {
                    throw new AppException(sprintf('Invalid user log flag at index %d', $flagIndex));
                }

                $logFlags[] = $flag;
            }

            $logFlags = implode(",", $logFlags);
            if (strlen($logFlags) > 255) {
                throw new AppException('User log flags exceed limit of 255 bytes');
            }
        }

        if ($controller && $line) {
            $controller = $controller . "#" . $line;
        }

        $db = AppKernel::getInstance()->db->primary();

        // Prepare Log model
        $log = new Log();
        $log->id = 0;
        $log->user = $user->id;
        $log->flags = $logFlags;
        $log->controller = $controller;
        $log->log = $message;
        $log->ipAddress = $ipAddress;
        $log->timeStamp = time();
        $log->query()->insert();
        $log->id = $db->lastInsertId();
        return $log;
    }
}
