<?php
declare(strict_types=1);

namespace App\Services\Admin\Controllers\Auth\PublicApi;

use App\Services\Admin\Controllers\Auth\AuthAdminAPIController;
use App\Services\Admin\Exception\AdminAPIException;
use Comely\Database\Schema;

/**
 * Class Queries
 * @package App\Services\Admin\Controllers\Auth\PublicApi
 */
class Queries extends AuthAdminAPIController
{
    /**
     * @return void
     * @throws \Comely\Database\Exception\DbConnectionException
     */
    protected function authCallback(): void
    {
        $apiLogsDb = $this->aK->db->apiLogs();
        Schema::Bind($apiLogsDb, 'App\Common\Database\PublicAPI\Queries');
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

    private function searchQueries(): void
    {
        // Where Query
        $whereQuery = [];
        $whereData = [];

        // Endpoint
        $endpoint = strtolower($this->input()->getASCII("endpoint"));
        if ($endpoint || $endpoint !== "/") {
            try {
                if (!preg_match('/^(\/[\w-]+)+$/', $endpoint)) {

                }

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

        try {

        } catch (AdminAPIException $e) {
            $e->setParam("endpoint");
            throw $e;
        }


    }

    public function get(): void
    {
        switch (strtolower($this->input()->getASCII("action"))) {
            case "count":
                $this->getSessionQueriesCount();
                return;
            case "search":
            case "query":
                $this->searchQueries();
                return;
            default:
                throw new AdminAPIException('Invalid "action" parameter called');
        }
    }
}
