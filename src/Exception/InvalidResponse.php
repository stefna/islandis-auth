<?php declare(strict_types=1);

namespace Islandis\Exception;

final class InvalidResponse extends \RuntimeException implements AuthenticateError, ResponseError
{
	public static function notWithinTimeframe(): self
	{
		return new self('Response is not within specified timeframe');
	}

	public static function dateInvalid(): self
	{
		return new self('Unable to get time from start (NotBefore) or end(NotOnOrAfter)');
	}

	public static function missingData(string ...$fields): self
	{
		if (count($fields) > 1) {
			return new self(sprintf('Missing fields "%s" from response', implode('", "', $fields)));
		}

		return new self(sprintf('Missing field "%s" from response', $fields[0]));
	}
}
