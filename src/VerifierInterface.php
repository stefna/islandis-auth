<?php declare(strict_types=1);

namespace Islandis;

interface VerifierInterface
{
	public function verify(string $token): bool;

	public function getAttribute(string $needle): ?string;
}
