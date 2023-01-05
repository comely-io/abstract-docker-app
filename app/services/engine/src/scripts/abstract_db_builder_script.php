<?php
declare(strict_types=1);

namespace bin;

use App\Common\Kernel\CLI\AbstractCLIScript;
use Comely\Database\Database;
use Comely\Database\Schema;

/**
 * Class abstract_db_builder_script
 * @package bin
 */
abstract class abstract_db_builder_script extends AbstractCLIScript
{
    /**
     * @return void
     * @throws \Comely\Database\Exception\DbConnectionException
     * @throws \Comely\Database\Exception\QueryExecuteException
     * @throws \Comely\Database\Exception\SchemaTableException
     */
    protected function createDbTables(): void
    {
        // Primary Database
        $this->inline("Getting {invert}{yellow} primary {/} database ... ");
        $primary = $this->aK->db->primary();
        $this->print("{green}OK{/}");

        $this->execDbTablesQuery($primary, [
            'App\Common\Database\Primary\Administrators',
            'App\Common\Database\Primary\Admin\Logs',
            'App\Common\Database\Primary\Admin\Sessions',
            'App\Common\Database\Primary\MailsQueue',
            'App\Common\Database\Primary\DataStore',
            'App\Common\Database\Primary\DbBackups',
            'App\Common\Database\Primary\ProcessTracker',
            'App\Common\Database\Primary\Countries',
            'App\Common\Database\Primary\Users\Groups',
            'App\Common\Database\Primary\Users',
            'App\Common\Database\Primary\Users\Logs',
            'App\Common\Database\Primary\Users\Profiles',
            'App\Common\Database\Primary\Users\Baggage',
        ]);

        $this->print("");

        // API Logs Database
        $this->inline("Getting {invert}{yellow} API Logs {/} database ... ");
        $apiLogs = $this->aK->db->apiLogs();
        $this->print("{green}OK{/}");

        $this->execDbTablesQuery($apiLogs, [
            'App\Common\Database\PublicAPI\Sessions',
            'App\Common\Database\PublicAPI\Queries',
            'App\Common\Database\PublicAPI\QueriesPayload',
        ]);

        $this->print("");
    }

    /**
     * @param Database $db
     * @param array $tables
     * @return void
     * @throws \Comely\Database\Exception\QueryExecuteException
     * @throws \Comely\Database\Exception\SchemaTableException
     */
    protected function execDbTablesQuery(Database $db, array $tables): void
    {
        $loaded = [];

        $this->print("{grey}Fetching tables... {/}");
        foreach ($tables as $tableClass) {
            $this->inline(sprintf('{cyan}%s{/} ... ', $tableClass));
            $tableName = constant(sprintf('%s::TABLE', $tableClass));
            Schema::Bind($db, $tableClass);
            $loaded[] = $tableName;
            $this->print("{green}OK{/}");
        }


        $this->print("");
        $this->print("{grey}Building database tables...{/}");
        foreach ($loaded as $table) {
            $this->inline(sprintf('CREATE' . ' TABLE IF NOT EXISTS `{cyan}%s{/}` ... ', $table));
            $migration = Schema::Migration($table)->createIfNotExists()->createTable();

            $db->exec($migration);
            $this->print('{green}SUCCESS{/}');
        }
    }

    /**
     * @return string|null
     */
    public function processInstanceId(): ?string
    {
        return null;
    }

    /**
     * @return string|null
     */
    public function semaphoreLockId(): ?string
    {
        return null;
    }
}
