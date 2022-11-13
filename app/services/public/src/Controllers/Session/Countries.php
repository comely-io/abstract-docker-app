<?php
declare(strict_types=1);

namespace App\Services\Public\Controllers\Session;

use App\Common\Countries\CachedCountriesList;
use Comely\Database\Schema;

/**
 * Class Countries
 * @package App\Services\Public\Controllers\Session
 */
class Countries extends AbstractSessionAPIController
{
    /**
     * @return void
     * @throws \Comely\Database\Exception\DbConnectionException
     */
    protected function sessionAPICallback(): void
    {
        $db = $this->aK->db->primary();
        Schema::Bind($db, 'App\Common\Database\Primary\Countries');
    }

    /**
     * @return void
     * @throws \Comely\Database\Exception\ORM_Exception
     * @throws \Comely\Database\Exception\SchemaTableException
     */
    public function get(): void
    {
        $countriesList = CachedCountriesList::getInstance(useCache: true, availableOnly: true);

        $this->status(true);
        $this->response->set("countries", $countriesList);
    }
}
