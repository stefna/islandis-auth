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

	public static function fromVerifier(Verifier $verifier): self
	{
		return new self(
			(string)$verifier->getAttribute('Nafn'),
			(string)$verifier->getAttribute('Kennitala'),
			(string)$verifier->getAttribute('Auðkenning'),
			(string)$verifier->getAttribute('IPTala'),
			(string)$verifier->getAttribute('NotandaStrengur'),
			(string)$verifier->getAttribute('KennitalaLögaðila'),
			(string)$verifier->getAttribute('NafnLögaðila')
		);
	}

	public function __construct(
		string $name,
		string $ssn,
		string $authMethod,
		string $ip,
		string $ua,
		string $legalEntitySsn,
		string $legalEntityName
	) {
		$this->name = $name;
		$this->ssn = $ssn;
		$this->authMethod = $authMethod;
		$this->ip = $ip;
		$this->ua = $ua;
		$this->legalEntitySsn = $legalEntitySsn;
		$this->legalEntityName = $legalEntityName;
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
}
