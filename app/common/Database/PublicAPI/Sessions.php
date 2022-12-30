<?php
declare(strict_types=1);

namespace App\Common\Database\PublicAPI;

use App\Common\Database\AbstractAppTable;
use App\Common\Database\Primary\Users;
use App\Common\Kernel\Databases;
use Comely\Database\Schema\Table\Columns;
use Comely\Database\Schema\Table\Constraints;

/**
 * Class Sessions
 * @package App\Common\Database\PublicAPI
 */
class Sessions extends AbstractAppTable
{
    public const TABLE = "sessions";
    public const ORM_CLASS = 'App\Common\PublicAPI\Session';

    /**
     * @param Columns $cols
     * @param Constraints $constraints
     * @return void
     */
    public function structure(Columns $cols, Constraints $constraints): void
    {
        $cols->defaults("ascii", "ascii_general_ci");

        $cols->int("id")->bytes(8)->unSigned()->autoIncrement();
        $cols->binary("checksum")->fixed(20);
        $cols->enum("type")->options("web", "app");
        $cols->int("archived")->bytes(1)->unSigned()->default(0);
        $cols->binary("token")->fixed(32)->unique();
        $cols->string("ip_address")->length(45);
        $cols->string("user_agent")->length(1024);
        $cols->binary("fingerprint")->fixed(32);
        $cols->int("auth_user_id")->bytes(4)->unSigned()->nullable();
        $cols->int("auth_session_otp")->bytes(1)->unSigned()->nullable();
        $cols->string("last_2fa_code")->fixed(6)->nullable();
        $cols->int("last_2fa_on")->bytes(4)->unSigned()->nullable();
        $cols->int("last_recaptcha_on")->bytes(4)->unSigned()->nullable();
        $cols->int("issued_on")->bytes(4)->unSigned();
        $cols->int("last_used_on")->bytes(4)->unSigned();
        $cols->primaryKey("id");

        // Foreign Keys
        $primaryDBName = $this->aK->config->db->get(Databases::PRIMARY)?->dbname;
        $constraints->foreignKey("auth_user_id")->database($primaryDBName)->table(Users::TABLE, "id");
    }
}
