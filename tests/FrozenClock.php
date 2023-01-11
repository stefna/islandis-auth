<?php declare(strict_types=1);

namespace Islandis\Tests;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;

final class FrozenClock implements ClockInterface
{
	public static function live(): self
	{
		return new self(new DateTimeImmutable());
	}

	public function __construct(
		private readonly DateTimeImmutable $now,
	) {}

	public function now(): DateTimeImmutable
	{
		return $this->now;
	}
}
