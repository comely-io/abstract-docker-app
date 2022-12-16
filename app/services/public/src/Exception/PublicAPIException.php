<?php
declare(strict_types=1);

namespace App\Services\Public\Exception;

use App\Common\Exception\AppControllerException;

/**
 * Class PublicAPIException
 * @package App\Services\Public\Exception
 */
class PublicAPIException extends AppControllerException
{
    /** @var string|null */
    private ?string $param = null;
    /** @var array|null */
    private ?array $data = null;

    /**
     * @param string $msg
     * @param string|null $param
     * @param int $code
     * @param \Throwable|null $prev
     * @param string|int|null ...$data
     * @return static
     */
    public static function Create(string $msg, ?string $param = null, int $code = 0, \Throwable $prev = null, ?array $data = null): static
    {
        $pex = new self($msg, $code, $prev);
        $pex->param = $param;
        $pex->data = $data;
        return $pex;
    }

    /**
     * @param string $param
     * @param string $msg
     * @param int $code
     * @param \Throwable|null $prev
     * @return static
     */
    public static function Param(string $param, string $msg, int $code = 0, ?\Throwable $prev = null): static
    {
        return (new self($msg, $code, $prev))->setParam($param);
    }

    /**
     * @param string $key
     * @return $this
     */
    public function setParam(string $key): self
    {
        $this->param = $key;
        return $this;
    }

    /**
     * @return string|null
     */
    public function getParam(): ?string
    {
        return $this->param;
    }

    /**
     * @param string|int ...$data
     * @return $this
     */
    public function setData(array $data): self
    {
        $this->data = $data;
        return $this;
    }

    /**
     * @return array|null
     */
    public function getData(): array|null
    {
        return $this->data;
    }
}
