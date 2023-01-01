<?php
declare(strict_types=1);

namespace App\Common\Users;

use Comely\Utils\OOP\Traits\NoDumpTrait;

/**
 * Class RecoveryCodes
 * @package App\Common\Users
 */
class RecoveryCodes
{
    /** @var int */
    private int $codesLen;
    /** @var array */
    private array $used;
    /** @var array */
    private array $unused;
    /** @var int */
    private int $generatedOn;

    use NoDumpTrait;

    /**
     * @param int $count
     * @param int $len
     */
    public function __construct(int $count = 6, int $len = 8)
    {
        $this->generatedOn = time();
        $this->codesLen = $len;
        $this->used = [];
        $this->unused = [];
        for ($i = 0; $i < $count; $i++) {
            $code = "";
            while (strlen($code) !== $len) {
                $char = mt_rand(0x30, 0x7a);
                if ($char < 0x3a || ($char > 0x40 && $char < 0x5b) || $char > 0x60) {
                    $code .= chr($char);
                }
            }

            $this->unused[] = $code;
        }
    }

    /**
     * @param string $code
     * @return bool
     */
    public function matchUnusedCode(string $code): bool
    {
        $code = preg_replace('/[^a-zA-Z0-9]/', '', $code);
        if (strlen($code) === $this->codesLen) {
            if (in_array($code, $this->unused, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param string $code
     * @return bool
     */
    public function redeemCode(string $code): bool
    {
        $code = preg_replace('/[^a-zA-Z0-9]/', '', $code);
        if (strlen($code) === $this->codesLen) {
            $codeIndex = array_search($code, $this->unused, true);
            if (is_int($codeIndex) && $codeIndex > -1) {
                $this->used[$code] = time();
                unset($this->unused[$codeIndex]);
                $this->unused = array_values($this->unused);
                return true;
            }
        }

        return false;
    }

    /**
     * @param int $showChars
     * @param int $chunkSplit
     * @param string $chunkSep
     * @param string $hideChar
     * @return array
     */
    public function dump(int $showChars, int $chunkSplit = 4, string $chunkSep = "-", string $hideChar = "*"): array
    {
        $codes = [];
        foreach ($this->unused as $unusedCode) {
            $codes[] = [
                "code" => $this->dumpCode($unusedCode, $showChars, $chunkSplit, $chunkSep, $hideChar),
                "usedOn" => null,
            ];
        }

        foreach ($this->used as $usedCode => $usedOn) {
            $codes[] = [
                "code" => $this->dumpCode($usedCode, $showChars, $chunkSplit, $chunkSep, $hideChar),
                "usedOn" => $usedOn
            ];
        }

        return [
            "generatedOn" => $this->generatedOn,
            "codes" => $codes,
            "usedCount" => count($this->used),
            "unusedCount" => count($this->unused)
        ];
    }

    /**
     * @param string $code
     * @param int $show
     * @param int $chunkSplit
     * @param string $chunkSep
     * @param string $hideChar
     * @return string
     */
    private function dumpCode(string $code, int $show, int $chunkSplit, string $chunkSep, string $hideChar): string
    {
        if ($show > 0) {
            $code = substr($code, 0, $show) . str_repeat($hideChar, strlen($code) - $show);
        }

        return trim(chunk_split($code, $chunkSplit, $chunkSep), $chunkSep);
    }
}
