<?php

declare(strict_types=1);

namespace Doomy\Security\Exception;

final class AuthenticationFailedException extends AbstractAuthenticatorException
{
    public function __construct(
        string $message = '',
        private readonly ?AbstractAuthenticatorException $previousException = null
    ) {
        parent::__construct($message);
    }

    public function getPreviousException(): ?AbstractAuthenticatorException
    {
        return $this->previousException;
    }
}
