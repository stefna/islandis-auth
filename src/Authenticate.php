<?php declare(strict_types=1);

namespace Islandis;

use Islandis\Exception\AuthenticateError;

class Authenticate
{
	/** @var Verifier */
	private $verifier;

	public function __construct(Verifier $verifier)
	{
		$this->verifier = $verifier;
	}

	/**
	 * @throws AuthenticateError
	 */
	public function verify(string $token): User
	{
		$this->verifier->verify($token);

		return User::fromVerifier($this->verifier);
	}
}
