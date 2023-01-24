<?php
declare(strict_types=1);

namespace App\Services\Admin\Controllers\Auth\PublicApi;

use App\Common\Database\Primary\Users;
use App\Common\Database\PublicAPI\QueriesPayload;
use App\Common\Exception\AppException;
use App\Common\Exception\AppModelNotFoundException;
use App\Common\PublicAPI\Query;
use App\Common\PublicAPI\QueryPayload;
use App\Common\Validator;
use App\Services\Admin\Controllers\Auth\AuthAdminAPIController;
use App\Services\Admin\Exception\AdminAPIException;
use Comely\Database\Exception\ORM_ModelNotFoundException;
use Comely\Database\Schema;
use Comely\Security\Exception\CipherException;

/**
 * Class Queries
 * @package App\Services\Admin\Controllers\Auth\PublicApi
 */
class Queries extends AuthAdminAPIController
{
    /** @var int[] */
    private const PER_PAGE_OPTS = [50, 100, 250, 500];

    /**
     * @return void
     * @throws \Comely\Database\Exception\DbConnectionException
     */
    protected function authCallback(): void
    {
        $apiLogsDb = $this->aK->db->apiLogs();
        Schema::Bind($apiLogsDb, 'App\Common\Database\PublicAPI\Queries');

        $db = $this->aK->db->primary();
        Schema::Bind($db, 'App\Common\Database\Primary\Users');
    }

    /**
     * @return void
     * @throws \App\Services\Admin\Exception\AdminAPIException
     * @throws \Comely\Database\Exception\DatabaseException
     */
    private function getSessionQueriesCount(): void
    {
        $sessionId = $this->input()->getInt("sessionId");
        if (!$sessionId || !($sessionId > 0)) {
            throw AdminAPIException::Param("sessionId", "Invalid session Id");
        }

        $db = $this->aK->db->apiLogs();
        $countQuery = $db->fetch(
            sprintf('SELECT ' . 'count(*) FROM `%s` WHERE `flag_api_sess`=%d',
                \App\Common\Database\PublicAPI\Queries::TABLE, $sessionId))->row();

        if (!isset($countQuery["count(*)"])) {
            throw new AdminAPIException('Failed to retrieve queries count');
        }

        $this->status(true);
        $this->response->set("count", (int)$countQuery["count(*)"]);
    }

    /**
     * @return void
     * @throws \App\Common\Exception\AppException
     * @throws \App\Services\Admin\Exception\AdminAPIException
     */
    private function searchQueries(): void
    {
        // Where Query
        $whereQuery = [];
        $whereData = [];

        // Endpoint
        $endpoint = strtolower($this->input()->getASCII("endpoint"));
        if ($endpoint && $endpoint !== "/") {
            try {
                if (!preg_match('/^(\/[\w\-.]+)+$/', $endpoint)) {
                    throw new AdminAPIException('Invalid endpoint/path');
                }

                $whereQuery[] = '`endpoint` LIKE ?';
                $whereData[] = $endpoint . "%";
            } catch (AdminAPIException $e) {
                $e->setParam("endpoint");
                throw $e;
            }
        }

        // HTTP Method
        $method = strtolower($this->input()->getASCII("method"));
        if ($method) {
            try {
                if (!in_array($method, ["post", "get", "put", "delete"])) {
                    throw new AdminAPIException('Invalid HTTP method to search for');
                }

                $whereQuery[] = "`method`=?";
                $whereData[] = $method;
            } catch (AdminAPIException $e) {
                $e->setParam("method");
                throw $e;
            }
        }

        // IP Address
        $ipAddress = $this->input()->getASCII("ipAddress");
        if ($ipAddress) {
            try {
                if (preg_match('/[^a-f0-9.:]+/', $ipAddress)) {
                    throw new AdminAPIException('IP address contains invalid character');
                }

                if (Validator::isValidIP($ipAddress, true)) { // Complete IP address
                    $whereQuery[] = '`ip_address`=?';
                    $whereData[] = $ipAddress;
                } else { // Incomplete IP address
                    $whereQuery[] = '`ip_address` LIKE ?';
                    $whereData[] = "%" . $ipAddress . "%";
                }
            } catch (AdminAPIException $e) {
                $e->setParam("ipAddress");
                throw $e;
            }
        }

        // API Session or User
        $sessUserFlag = strtolower($this->input()->getASCII("sessUserFlag"));
        if ($sessUserFlag) {
            try {
                if (preg_match('/^[1-9][0-9]+$/', $sessUserFlag)) { // Possible session ID
                    $whereQuery[] = "`flag_api_sess`=?";
                    $whereData[] = intval($sessUserFlag);
                } else { // Should be username
                    if (!Validator::isValidUsername($sessUserFlag)) {
                        throw new AdminAPIException('Invalid username');
                    }

                    try {
                        $user = Users::Get(username: $sessUserFlag, useCache: true);
                    } catch (AppModelNotFoundException) {
                        throw new AdminAPIException('No such user account exists');
                    }

                    $whereQuery[] = "`flag_user_id`=?";
                    $whereData[] = $user->id;
                }
            } catch (AdminAPIException $e) {
                $e->setParam("sessUserFlag");
                throw $e;
            }
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

        if (!$whereQuery) {
            $whereQuery[] = 1;
        }

        // Result Prep
        $result = [
            "totalRows" => 0,
            "page" => null,
            "rows" => null
        ];

        try {
            $queriesSearch = $this->aK->db->apiLogs()->query()
                ->table(\App\Common\Database\PublicAPI\Queries::TABLE)
                ->where(implode(" AND ", $whereQuery), $whereData)
                ->start(($pageNum * $perPage) - $perPage)
                ->limit($perPage);

            if ($sortBy === "asc") {
                $queriesSearch->asc("id");
            } else {
                $queriesSearch->desc("id");
            }

            $queriesSearch = $queriesSearch->paginate();
            $result["totalRows"] = $queriesSearch->totalRows();
            $result["page"] = $pageNum;
            $result["perPage"] = $perPage;
        } catch (\Exception $e) {
            $this->aK->errors->triggerIfDebug($e, E_USER_WARNING);
            throw new AdminAPIException('Failed to execute API queries fetch query');
        }

        $queries = [];
        foreach ($queriesSearch->rows() as $row) {
            unset($query);

            try {
                $query = new Query($row);

                try {
                    $query->validateChecksum();
                } catch (AppException) {
                }

                $queries[] = $query;
            } catch (\Exception $e) {
                $this->aK->errors->trigger($e, E_USER_WARNING);
                continue;
            }
        }

        try {
            $result["rows"] = Validator::JSON_Filter($queries);
        } catch (\JsonException) {
            throw new AdminAPIException('Failed to pass JSON filter on result');
        }

        $this->status(true);
        $this->response->set("queries", $result);
    }

    /**
     * @return void
     * @throws \App\Common\Exception\AppException
     * @throws \App\Services\Admin\Exception\AdminAPIException
     * @throws \Comely\Database\Exception\DatabaseException
     */
    private function getSpecificQuery(): void
    {
        try {
            $queryId = $this->input()->getInt("query");
            if (!$queryId || !($queryId > 0)) {
                throw new AdminAPIException("Invalid public API query id");
            }

            try {
                /** @var Query $query */
                $query = \App\Common\Database\PublicAPI\Queries::Find()->query('WHERE `id`=?', [$queryId])->first();
            } catch (ORM_ModelNotFoundException) {
                throw new AdminAPIException("No such API query exists");
            }
        } catch (AdminAPIException $e) {
            $e->setParam("query");
            throw $e;
        }

        $payloadError = null;
        try {
            if (!$this->admin->privileges()->isRoot()) {
                if (!$this->admin->privileges()->viewAPIQueriesPayload) {
                    throw new AdminAPIException('You do not have privilege to view queries payload');
                }
            }

            $payloadRow = $this->aK->db->apiLogs()->query()->table(QueriesPayload::TABLE)
                ->where("`query`=?", [$query->id])
                ->fetch();
            if ($payloadRow->count() !== 1) {
                throw new AdminAPIException('Query payload data not stored');
            }

            $encrypted = $payloadRow->row()["encrypted"] ?? null;
            if (!$encrypted || !is_string($encrypted)) {
                throw new AdminAPIException('Could not retrieve encrypted bytes');
            }

            try {
                $payload = $this->aK->ciphers->secondary()->decrypt($encrypted);
                if (!$payload instanceof QueryPayload) {
                    throw new AdminAPIException(
                        sprintf('Expected instance of "QueryPayload" got "%s"',
                            is_object($payload) ? get_class($payload) : gettype($payload))
                    );
                }
            } catch (CipherException) {
                throw new AdminAPIException('Failed to decrypt API query payload');
            }
        } catch (AdminAPIException $e) {
            $payloadError = $e->getMessage();
        }

        if ($query->startOn && $query->endOn) {
            $queryTimespan = bcsub(strval($query->startOn), strval($query->endOn), 4);
        }

        if ($query->flagUserId) {
            $queryFlagusername = Users::CachedUsername($query->flagUserId);
        }

        try {
            $query = Validator::JSON_Filter($query);
        } catch (\JsonException) {
            throw new AdminAPIException('Failed to pass JSON filter to query object');
        }

        $query["timespan"] = $queryTimespan ?? null;
        $query["flagUsername"] = $queryFlagusername ?? null;
        if (isset($payload) && !$payloadError) {
            $query["payload"] = $payload->array();
        } else {
            $query["payloadError"] = $payloadError;
        }

        $this->status(true);
        $this->response->set("query", $query);
    }

    /**
     * @return void
     * @throws \App\Common\Exception\AppException
     * @throws \App\Services\Admin\Exception\AdminAPIException
     * @throws \Comely\Database\Exception\DatabaseException
     */
    public function get(): void
    {
        switch (strtolower($this->input()->getASCII("action"))) {
            case "count":
                $this->getSessionQueriesCount();
                return;
            case "search":
                $this->searchQueries();
                return;
            case "query":
                $this->getSpecificQuery();
                return;
            default:
                throw new AdminAPIException('Invalid "action" parameter called');
        }
    }
}
