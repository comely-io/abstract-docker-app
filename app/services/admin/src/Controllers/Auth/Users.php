<?php
declare(strict_types=1);

namespace App\Services\Admin\Controllers\Auth;

use App\Common\Exception\AppException;
use App\Common\Exception\AppModelNotFoundException;
use App\Common\Users\User;
use App\Common\Validator;
use App\Services\Admin\Exception\AdminAPIException;
use Comely\Database\Schema;

/**
 * Class Users
 * @package App\Services\Admin\Controllers\Auth
 */
class Users extends AuthAdminAPIController
{
    /** @var int[] */
    private const PER_PAGE_OPTS = [25, 50, 100, 250];

    /**
     * @return void
     * @throws AdminAPIException
     * @throws \App\Common\Exception\AppException
     * @throws \Comely\Database\Exception\DatabaseException
     */
    protected function authCallback(): void
    {
        $db = $this->aK->db->primary();
        Schema::Bind($db, 'App\Common\Database\Primary\Users\Groups');
        Schema::Bind($db, 'App\Common\Database\Primary\Users');

        $privileges = $this->admin->privileges();
        if (!$privileges->isRoot() && !$privileges->viewUsers) {
            throw new AdminAPIException('You are not privileged for user management');
        }
    }

    /**
     * @return void
     * @throws \App\Services\Admin\Exception\AdminAPIException
     */
    private function getCachedUsernames(): void
    {
        $ids = array_filter(array_unique(explode(",", trim($this->input()->getASCII("id")))), "intval");
        if (!$ids) {
            throw AdminAPIException::Param("id", "No user IDs received");
        }

        $usernames = \App\Common\Database\Primary\Users::CachedUsernames(...$ids);

        $this->status(true);
        $this->response->set("usernames", $usernames);
    }

    /**
     * @return void
     * @throws AdminAPIException
     * @throws AppException
     */
    public function get(): void
    {
        // Action: Usernames?
        if (strtolower($this->input()->getASCII("action")) === "usernames") {
            $this->getCachedUsernames();
            return;
        }

        // Where Query
        $whereQuery = [];
        $whereData = [];

        // Search
        $searchValue = $this->input()->getASCII("search");
        if ($searchValue) {
            $whereQuery[] = "(`username` LIKE ? OR `email` LIKE ? OR `phone` LIKE ?)";
            $whereData[] = sprintf("%%%s%%", $searchValue);
            $whereData[] = sprintf("%%%s%%", $searchValue);
            $whereData[] = sprintf("%%%s%%", $searchValue);
        }

        // Referrer
        $referrerId = $this->input()->getASCII("referrer");
        if ($referrerId) {
            try {
                if (!Validator::isValidUsername($referrerId)) {
                    throw new AdminAPIException('Invalid referrer username');
                }

                try {
                    $referrerAccount = \App\Common\Database\Primary\Users::Get(username: $referrerId, useCache: true);
                } catch (AppModelNotFoundException) {
                    throw new AdminAPIException('No such referrer account exists');
                }

                $whereQuery[] = "`referrer_id`=?";
                $whereData[] = $referrerAccount->id;
            } catch (AdminAPIException $e) {
                $e->setParam("referrer");
                throw $e;
            }
        }

        // Group ID
        $groupId = $this->input()->getInt("group_id", unSigned: true);
        if (is_int($groupId) && $groupId > 0) {
            $whereQuery[] = "`group_id`=?";
            $whereData[] = $groupId;
        }

        // Archived
        $archived = strtolower($this->input()->getASCII("archived"));
        if (!$archived) {
            $archived = "exclude";
        }

        if (!in_array($archived, ["exclude", "include", "just"])) {
            throw AdminAPIException::Param("archived", "Invalid value for archived");
        }

        switch ($archived) {
            case "exclude":
                $whereQuery[] = "`archived`=0";
                break;
            case "just":
                $whereQuery[] = "`archived`=1";
                break;
        }

        // Status
        $status = strtolower($this->input()->getASCII("status"));
        if (!$status) {
            $status = "any";
        }

        if (!in_array($status, ["active", "disabled", "any"])) {
            throw AdminAPIException::Param("archived", "Invalid value for status");
        }

        switch ($status) {
            case "active":
                $whereQuery[] = "`status`='active'";
                break;
            case "disabled":
                $whereQuery[] = "`status`='disabled'";
                break;
        }

        // Sort By
        $sortBy = strtolower($this->input()->getASCII("sort"));
        if (!$sortBy) {
            $sortBy = "desc";
        }

        if (!in_array($sortBy, ["desc", "asc"])) {
            throw AdminAPIException::Param("sort", "Invalid sort value");
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

        try {
            $usersQuery = $this->aK->db->primary()->query()
                ->table(\App\Common\Database\Primary\Users::TABLE)
                ->where(implode(" AND ", $whereQuery), $whereData)
                ->start(($pageNum * $perPage) - $perPage)
                ->limit($perPage);

            if ($sortBy === "asc") {
                $usersQuery->asc("id");
            } else {
                $usersQuery->desc("id");
            }

            $usersQuery = $usersQuery->paginate();
            $result["totalRows"] = $usersQuery->totalRows();
            $result["page"] = $pageNum;
            $result["perPage"] = $perPage;
        } catch (\Exception $e) {
            $this->aK->errors->triggerIfDebug($e, E_USER_WARNING);
            throw new AdminAPIException('Failed to execute users fetch query');
        }

        $users = [];
        foreach ($usersQuery->rows() as $row) {
            unset($user);

            try {
                $user = new User($row);
                try {
                    $user->validateChecksum();
                    $user->checksumVerified = true;
                } catch (AppException) {
                    $user->checksumVerified = false;
                }

                $users[] = $user;
            } catch (\Exception $e) {
                $this->aK->errors->trigger($e, E_USER_WARNING);
                continue;
            }
        }

        $result["rows"] = $users;

        $this->status(true);
        $this->response->set("users", $result);
    }
}
