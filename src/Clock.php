<?php declare(strict_types=1);

namespace Islandis;

final class Clock
{
	/** @var int|null */
	private $fixedTime;

	public static function fixed(string $time): self
	{
		return new self((int)strtotime($time));
	}

	public static function live(): self
	{
		return new self(null);
	}

	private function __construct(?int $time)
	{
		$this->fixedTime = $time;
	}

	public function getTimestamp(): int
	{
		return $this->fixedTime ?? time();
	}
}
