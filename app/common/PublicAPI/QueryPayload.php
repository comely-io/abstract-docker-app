<?php
declare(strict_types=1);

namespace App\Common\PublicAPI;

use App\Common\AppKernel;
use App\Services\Public\Controllers\AbstractPublicAPIController;
use Comely\Database\Queries\DbQueryExec;

/**
 * Class QueryPayload
 * @package App\Common\PublicAPI
 */
class QueryPayload
{
    /** @var int */
    private int $query;
    /** @var array */
    private array $reqHeaders;
    /** @var array */
    private array $resHeaders;
    /** @var array */
    private array $reqBody;
    /** @var null|string */
    private ?string $resBody;
    /** @var array */
    private array $dbQueries;
    /** @var array */
    private array $errors;

    /**
     * @param Query $query
     * @param AbstractPublicAPIController $controller
     * @param string|null $body
     */
    public function __construct(Query $query, AbstractPublicAPIController $controller, ?string $body)
    {
        $aK = AppKernel::getInstance();
        $this->query = $query->id;
        $this->reqHeaders = $controller->request->headers->array();
        $this->resHeaders = $controller->response->headers->array();

        // Request Body
        $requestBody = $controller::QL_SAVE_REQ_PARAMS ? $controller->request->payload->array() : [];
        if ($requestBody) {
            $ignoreReqParams = $controller::QL_IGNORE_REQ_PARAMS;
            if ($ignoreReqParams) {
                foreach ($ignoreReqParams as $ignoreReqParam) {
                    unset($requestBody[$ignoreReqParam]);
                }
            }
        }

        $this->reqBody = $requestBody;
        $this->resBody = $controller::QL_SAVE_RES_BODY ? $body : null;
        $this->errors = $aK->errors->all();

        // Database Queries
        $this->dbQueries = [];
        foreach ($aK->db->getAllQueries() as $dbQuery) {
            /** @var DbQueryExec $dbQueryInstance */
            $dbQueryInstance = $dbQuery["query"];
            $thisQuery = [
                "db" => $dbQuery["db"],
                "query" => [
                    "sql" => $dbQueryInstance->queryString(),
                    "data" => json_encode($dbQueryInstance->boundData()),
                    "rows" => $dbQueryInstance->rows(),
                    "error" => null,
                ]
            ];

            if ($dbQueryInstance->error()) {
                $thisQuery["error"] = [
                    "code" => $dbQueryInstance->error()->code,
                    "info" => $dbQueryInstance->error()->info,
                    "sqlState" => $dbQueryInstance->error()->sqlState
                ];
            }

            $this->dbQueries[] = $thisQuery;
            unset($thisQuery);
        }
    }

    /**
     * @return array
     */
    public function array(): array
    {
        return [
            "query" => $this->query,
            "reqHeaders" => $this->reqHeaders,
            "resHeaders" => $this->resHeaders,
            "reqBody" => $this->reqBody,
            "resBody" => $this->resBody,
            "dbQueries" => $this->dbQueries,
            "errors" => $this->errors
        ];
    }
}
