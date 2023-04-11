<?php declare(strict_types=1);

namespace Islandis;

use Islandis\Exception\AuthenticateError;

class Authenticate
{
	public function __construct(
		private readonly VerifierInterface $verifier,
	) {}

	/**
	 * @throws AuthenticateError
	 */
	public function verify(string $token): User
	{
		$this->verifier->verify($token);

		return User::fromVerifier($this->verifier);
	}
}
