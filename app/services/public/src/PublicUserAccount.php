<?php
declare(strict_types=1);

namespace App\Services\Public;

use App\Common\Users\User;

/**
 * Class PublicUserAccount
 * @package App\Services\Public
 */
class PublicUserAccount
{
    /** @var string */
    public readonly string $username;
    /** @var int */
    public readonly int $groupId;
    /** @var string */
    public readonly string $status;
    /** @var bool */
    public readonly bool $isDeleted;
    /** @var string|null */
    public readonly ?string $email;
    /** @var bool */
    public readonly bool $emailVerified;
    /** @var string|null */
    public readonly ?string $phone;
    /** @var bool */
    public readonly bool $phoneVerified;
    /** @var int */
    public readonly int $registeredOn;
    /** @var array */
    public readonly array $tags;

    /**
     * @param User $user
     */
    public function __construct(User $user)
    {
        $this->username = $user->username;
        $this->groupId = $user->groupId;
        $this->status = $user->status;
        $this->isDeleted = $user->archived !== 0;
        $this->email = $user->email;
        $this->emailVerified = $user->emailVerified === 1;
        $this->phone = $user->phone;
        $this->phoneVerified = $user->phoneVerified === 1;
        $this->registeredOn = $user->createdOn;
        $this->tags = $user->tags();
    }
}
