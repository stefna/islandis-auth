<?php declare(strict_types=1);

namespace Islandis;

class User
{
	/** @var string */
	private $name;
	/** @var string */
	private $ssn;
	/** @var string */
	private $authMethod;
	/** @var string */
	private $ip;
	/** @var string */
	private $ua;
	/** @var string */
	private $legalEntitySsn;
	/** @var string */
	private $legalEntityName;
	/** @var string */
	private $destinationSsn;
	/** @var string */
	private $authId;
	/** @var string */
	private $mobile;

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
		string $name,
		string $ssn,
		string $authMethod,
		string $ip,
		string $ua,
		string $legalEntitySsn,
		string $legalEntityName,
		string $destinationSsn,
		string $authId,
		string $mobile
	) {
		$this->name = $name;
		$this->ssn = $ssn;
		$this->authMethod = $authMethod;
		$this->ip = $ip;
		$this->ua = $ua;
		$this->legalEntitySsn = $legalEntitySsn;
		$this->legalEntityName = $legalEntityName;
		$this->destinationSsn = $destinationSsn;
		$this->authId = $authId;
		$this->mobile = $mobile;
	}

	public function getName(): string
	{
		return $this->name;
	}

	public function getKennitala(): string
	{
		return $this->ssn;
	}

	public function getAuthenticationMethod(): string
	{
		return $this->authMethod;
	}

	public function getUserIp(): string
	{
		return $this->ip;
	}

	public function getUserAgent(): string
	{
		return $this->ua;
	}

	public function getLegalEntityKennitala(): string
	{
		return $this->legalEntitySsn;
	}

	public function getLegalEntityName(): string
	{
		return $this->legalEntityName;
	}

	public function getDestinationSsn(): string
	{
		return $this->destinationSsn;
	}

	public function getAuthId(): string
	{
		return $this->authId;
	}

	public function getMobile(): string
	{
		return $this->mobile;
	}
}
