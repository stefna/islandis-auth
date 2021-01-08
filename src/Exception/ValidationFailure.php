<?php declare(strict_types=1);

namespace Islandis\Exception;

final class ValidationFailure extends \DomainException implements AuthenticateError
{
	public static function reference(\Exception $e): self
	{
		return new self('Reference Validation Failed', 1, $e);
	}

	public static function userAgent(): self
	{
		return new self('User-agent does not match');
	}

	public static function ip(): self
	{
		return new self('Invalid IP address.');
	}

	public static function keyNotFound(): self
	{
		return new self('Key not found');
	}

	public static function invalidAudience(string $audience, string $expected): self
	{
		return new self(sprintf('Invalid audience expected "%s" got "%s"', $expected, $audience));
	}

	public static function keyInfoNotFound(): self
	{
		return new self('Failed to extract info from key');
	}
}
