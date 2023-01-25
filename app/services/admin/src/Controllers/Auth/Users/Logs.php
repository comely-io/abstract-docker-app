<?php
declare(strict_types=1);

namespace App\Services\Admin\Controllers\Auth\Users;

use App\Common\Database\Primary\Users;
use App\Common\Exception\AppModelNotFoundException;
use App\Common\Users\Log;
use App\Common\Validator;
use App\Services\Admin\Controllers\Auth\AuthAdminAPIController;
use App\Services\Admin\Exception\AdminAPIException;
use Comely\Database\Schema;

/**
 * Class Logs
 * @package App\Services\Admin\Controllers\Auth\Users
 */
class Logs extends AuthAdminAPIController
{
    /** @var int[] */
    private const PER_PAGE_OPTS = [25, 50, 100, 250];

    /**
     * @return void
     * @throws \Comely\Database\Exception\DbConnectionException
     */
    protected function authCallback(): void
    {
        $db = $this->aK->db->primary();
        Schema::Bind($db, 'App\Common\Database\Primary\Users');
        Schema::Bind($db, 'App\Common\Database\Primary\Users\Logs');
    }

    /**
     * @return void
     * @throws \App\Common\Exception\AppException
     * @throws \App\Services\Admin\Exception\AdminAPIException
     */
    public function get(): void
    {
        // Privilege check
        $privileges = $this->admin->privileges();
        if (!$privileges->isRoot() && !$privileges->manageUsers) {
            throw new AdminAPIException('You are not privileged to view other users logs');
        }

        // Username
        $username = $this->input()->getASCII("username");
        if ($username) {
            try {
                if (!Validator::isValidUsername($username)) {
                    throw new AdminAPIException('Invalid username');
                }

                try {
                    $user = Users::Get(username: $username, useCache: true);
                } catch (AppModelNotFoundException) {
                    throw new AdminAPIException('No such user account is registered');
                }
            } catch (AdminAPIException $e) {
                $e->setParam("username");
                throw $e;
            }
        }

        // Page Sorting
        $pageNum = $this->input()->getInt("page", true) ?? 1;
        $perPage = $this->input()->getInt("perPage", true) ?? self::PER_PAGE_OPTS[0];
        if (!in_array($perPage, self::PER_PAGE_OPTS)) {
            throw new AdminAPIException('Invalid value for "perPage" param');
        }

        // Result Prep
        $result = [
            "totalRows" => 0,
            "page" => null,
            "rows" => null
        ];

        // Query Builder
        $whereQuery = "1";
        $whereData = [];

        if (isset($user)) {
            $whereQuery .= ' AND `user`=?';
            $whereData[] = $user->id;
        }

        // Search filters
        $flags = $this->input()->getASCII("flags");
        if ($flags) {
            $flags = preg_split('/[\s,]+/', $flags);
            if (is_array($flags) && isset($flags[0])) {
                $whereQuery .= ' AND (';
                $fI = -1;
                foreach ($flags as $flag) {
                    $fI++;
                    $flag = trim($flag);
                    if (!$flag) {
                        continue;
                    }

                    if ($fI !== 0) {
                        $whereQuery .= ' OR ';
                    }

                    $whereQuery .= 'INSTR(`flags`, ?) > 0';
                    $whereData[] = $flag;
                }

                $whereQuery .= ')';
            }
        }

        // Log message
        $filter = $this->input()->getASCII("filter");
        if ($filter) {
            $whereQuery .= ' AND `log` LIKE ?';
            $whereData[] = sprintf('%%%s%%', $filter);
        }

        try {
            $logsQuery = $this->aK->db->primary()->query()
                ->table(\App\Common\Database\Primary\Users\Logs::TABLE)
                ->where($whereQuery, $whereData)
                ->desc("id")
                ->start(($pageNum * $perPage) - $perPage)
                ->limit($perPage)
                ->paginate();

            $result["totalRows"] = $logsQuery->totalRows();
            $result["page"] = $pageNum;
            $result["perPage"] = $perPage;
        } catch (\Exception $e) {
            $this->aK->errors->triggerIfDebug($e, E_USER_WARNING);
            throw new AdminAPIException('Failed to execute logs fetch query');
        }

        $logs = [];
        foreach ($logsQuery->rows() as $row) {
            try {
                $log = new Log($row);
                $log->flags = $log->flags ? explode(",", $log->flags) : null;
                $logs[] = $log;
            } catch (\Exception $e) {
                $this->aK->errors->trigger($e, E_USER_WARNING);
                continue;
            }
        }

        $result["rows"] = $logs;

        $this->status(true);
        $this->response->set("logs", $result);
    }
}
