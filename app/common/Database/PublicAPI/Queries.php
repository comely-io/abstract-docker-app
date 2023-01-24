<?php
declare(strict_types=1);

namespace App\Common\Database\PublicAPI;

use App\Common\Database\AbstractAppTable;
use App\Common\Database\Primary\Users;
use App\Common\Kernel\Databases;
use Comely\Database\Schema\Table\Columns;
use Comely\Database\Schema\Table\Constraints;

/**
 * Class Queries
 * @package App\Common\Database\PublicAPI
 */
class Queries extends AbstractAppTable
{
    public const TABLE = "queries";
    public const ORM_CLASS = 'App\Common\PublicAPI\Query';

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
        $cols->string("ip_address")->length(45);
        $cols->string("method")->length(8);
        $cols->string("endpoint")->length(512);
        $cols->double("start_on")->precision(14, 4)->unSigned();
        $cols->double("end_on")->precision(14, 4)->unSigned();
        $cols->int("res_code")->bytes(2)->unSigned()->nullable();
        $cols->int("res_len")->bytes(4)->unSigned()->nullable();
        $cols->int("flag_api_sess")->bytes(8)->unSigned()->nullable();
        $cols->int("flag_user_id")->bytes(4)->unSigned()->nullable();
        $cols->primaryKey("id");

        // Foreign Keys
        $primaryDBName = $this->aK->config->db->get(Databases::PRIMARY)?->dbname;
        $constraints->foreignKey("flag_api_sess")->table(Sessions::TABLE, "id");
        $constraints->foreignKey("flag_user_id")->database($primaryDBName)->table(Users::TABLE, "id");
    }
}
