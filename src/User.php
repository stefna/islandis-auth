<?php declare(strict_types=1);

namespace Islandis;

class User
{
	public static function fromVerifier(Verifier $verifier): self
	{
		return new self(
			(string)$verifier->getAttribute('Name'),
			(string)$verifier->getAttribute('UserSSN'),
			(string)$verifier->getAttribute('Authentication'),
			(string)$verifier->getAttribute('IPAddress'),
			(string)$verifier->getAttribute('UserAgent'),
			(string)$verifier->getAttribute('CompanySSN'),
			(string)$verifier->getAttribute('CompanyName'),
			(string)$verifier->getAttribute('DestinationSSN'),
			(string)$verifier->getAttribute('AuthID'),
			(string)$verifier->getAttribute('Mobile')
		);
	}

	public function __construct(
		public readonly string $name,
		public readonly string $ssn,
		public readonly string $authenticationMethod,
		public readonly string $ip,
		public readonly string $ua,
		public readonly string $legalEntitySsn,
		public readonly string $legalEntityName,
		public readonly string $destinationSsn,
		public readonly string $authId,
		public readonly string $mobile
	) {}

	public function getName(): string
	{
		return $this->name;
	}

	public function getKennitala(): string
	{
		return $this->ssn;
	}
}
