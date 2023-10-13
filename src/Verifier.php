<?php declare(strict_types=1);

namespace Islandis;

use DOMNode;
use DOMDocument;
use DOMXPath;
use Exception;
use Islandis\Exception\CertificateError;
use Islandis\Exception\InvalidResponse;
use Islandis\Exception\ValidationFailure;
use Islandis\Exception\XmlError;
use phpseclib3\File\X509;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

final class Verifier
{
	const INTERMEDIATE_COMMON_NAME = 'Fullgilt audkenni';
	/** @var DOMDocument|null */
	private $xml;
	/** @var string */
	private $myCertPem;
	/** @var string */
	private $intermediateCert;
	/** @var string */
	private $audienceUrl;
	/** @var Clock */
	private $clock;
	/** @var string */
	private $userAgent;
	/** @var XMLSecurityKey|null */
	private $objKeyInfo;
	/** @var XMLSecurityDSig */
	private $objXMLSecDSig;
	/** @var DOMNode */
	private $objDSig;

	public function __construct(string $audienceUrl, ?string $certificateDir = null)
	{
		$this->clock = Clock::live();
		if ($certificateDir === null) {
			$certificateDir = $this->getDefaultCertificateFolder();
		}
		$this->myCertPem = $certificateDir . DIRECTORY_SEPARATOR . 'mycert.pem';
		$this->intermediateCert = $certificateDir . DIRECTORY_SEPARATOR . 'Milliskilriki.cer';

		if (!file_exists($this->intermediateCert)) {
			throw CertificateError::notFoundInDirectory($certificateDir);
		}
		$this->audienceUrl = $audienceUrl;
	}

	public function setClock(Clock $clock): void
	{
		$this->clock = $clock;
	}

	public function setUserAgent(string $agent): void
	{
		$this->userAgent = $agent;
	}

	public function verify(string $token): bool
	{
		if (!$token) {
			throw new \InvalidArgumentException('Can\'t verify empty token');
		}

		$this->loadXml($token);

		$this->verifyDate();
		$this->verifyAudience();
		$this->verifyUserAgent();
		$this->verifyReference();
		$this->verifySignature();
		$this->verifyCertificate();

		return true;
	}

	public function getAttribute(string $needle): ?string
	{
		$node = $this->queryDocument([
			'/protocol:Response',
			'/assertion:Assertion',
			'//assertion:Attribute[@Name="' . $needle . '"]',
			'/assertion:AttributeValue',
		]);

		return $node ? $node->nodeValue : null;
	}

	private function getDefaultCertificateFolder(): string
	{
		return \dirname(__DIR__) . DIRECTORY_SEPARATOR . 'certificates';
	}

	private function loadXml(string $token): void
	{
		// Avoid warnings
		$previous = libxml_use_internal_errors(true);
		$this->xml = new DOMDocument();
		if (!$this->xml->loadXML(base64_decode($token))) {
			throw XmlError::libXML(libxml_get_last_error());
		}
		libxml_use_internal_errors($previous);
	}

	private function getUserAgent(): string
	{
		if ($this->userAgent) {
			return $this->userAgent;
		}

		$useragent = '';
		if (!empty($_SERVER['HTTP_USER_AGENT'])) {
			$useragent = $_SERVER['HTTP_USER_AGENT'];
		}

		return $useragent;
	}

	private function verifyUserAgent(): void
	{
		$userAgent = $this->getUserAgent();
		$expected = $this->getAttribute('UserAgent');

		if ($expected !== $userAgent) {
			throw ValidationFailure::userAgent($userAgent, $expected);
		}
	}

	private function verifyDate(): bool
	{
		/** @var \DOMElement|null $conditions */
		$conditions = $this->queryDocument(['/protocol:Response', '/assertion:Assertion', '/assertion:Conditions']);
		if (!$conditions) {
			throw InvalidResponse::missingData('Conditions');
		}

		$start = $conditions->getAttribute('NotBefore');
		$end = $conditions->getAttribute('NotOnOrAfter');
		if (!$start || !$end) {
			throw InvalidResponse::missingData('NotBefore', 'NotOnOrAfter');
		}

		date_default_timezone_set('Atlantic/Reykjavik');
		$startTime = strtotime($start);
		$endTime = strtotime($end);
		if (!\is_int($startTime) || !\is_int($endTime)) {
			throw InvalidResponse::dateInvalid();
		}
		$now = $this->clock->getTimestamp();
		$inSpan = $startTime < $now && $now < $endTime;
		if (!$inSpan) {
			throw InvalidResponse::notWithinTimeframe();
		}
		return true;
	}

	private function verifyCertificate(): bool
	{
		if (!$this->objKeyInfo) {
			throw ValidationFailure::keyInfoNotFound();
		}
		$leaf = new X509();
		if (!$leaf->loadX509($this->objKeyInfo->getX509Certificate())) {
			throw CertificateError::readError();
		}
		if (!$leaf->loadCA((string)file_get_contents($this->intermediateCert))) {
			throw CertificateError::readError();
		}

		date_default_timezone_set('Atlantic/Reykjavik');
		if (!$leaf->validateDate($this->clock->getDateTime())) {
			throw CertificateError::expired();
		}

		if ($leaf->getSubjectDNProp('serialNumber')[0] !== '6503760649') {
			throw CertificateError::invalidSubject($leaf->getSubjectDNProp('serialNumber')[0]);
		}

		if ($leaf->getIssuerDNProp('commonName')[0] !== self::INTERMEDIATE_COMMON_NAME) {
			throw CertificateError::invalidIssuer($leaf->getIssuerDNProp('commonName')[0] ?? '');
		}

		if (!$leaf->validateSignature()) {
			throw CertificateError::signatureInvalid();
		}

		return true;
	}

	private function verifyAudience(): bool
	{
		$audience = $this->queryDocument([
			'/protocol:Response',
			'/assertion:Assertion',
			'/assertion:Conditions',
			'/assertion:AudienceRestriction',
			'/assertion:Audience',
		]);

		if (!$audience || $audience->textContent !== $this->audienceUrl) {
			throw ValidationFailure::invalidAudience($audience ? $audience->textContent : '', $this->audienceUrl);
		}

		return true;
	}

	private function verifySignature(): void
	{
		$objKey = $this->objXMLSecDSig->locateKey();
		if (!$objKey) {
			throw ValidationFailure::keyNotFound();
		}
		$key = null;
		$this->objKeyInfo = XMLSecEnc::staticLocateKeyInfo($objKey, $this->objDSig);
		if (!$this->objKeyInfo) {
			throw ValidationFailure::keyInfoNotFound();
		}
		if (!$this->objKeyInfo->key && empty($key)) {
			$objKey->loadKey($this->myCertPem, true);
		}
		if (!$this->objXMLSecDSig->verify($objKey)) {
			throw CertificateError::signatureInvalid();
		}
	}

	private function verifyReference(): void
	{
		if (!$this->xml) {
			throw XmlError::notLoaded();
		}
		$objXMLSecDSig = new XMLSecurityDSig();
		$objDSig = $objXMLSecDSig->locateSignature($this->xml);

		if ($objDSig === null) {
			throw XmlError::missingSignature();
		}

		$objXMLSecDSig->canonicalizeSignedInfo();
		$objXMLSecDSig->idKeys = ['ID'];
		$objXMLSecDSig->idNS = [
			'wsu' => 'http://docs.oasisopen.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
		];
		try {
			$objXMLSecDSig->validateReference();

			$this->objXMLSecDSig = $objXMLSecDSig;
			$this->objDSig = $objDSig;
		}
		catch (\Exception $e) {
			throw ValidationFailure::reference($e);
		}
	}

	/**
	 * @param string[] $fields
	 */
	private function queryDocument(array $fields): ?DOMNode
	{
		if (!$this->xml) {
			throw XmlError::notLoaded();
		}

		try {
			$xpath = new DOMXPath($this->xml);
			$xpath->registerNamespace('assertion', 'urn:oasis:names:tc:SAML:2.0:assertion');
			$xpath->registerNamespace('protocol', 'urn:oasis:names:tc:SAML:2.0:protocol');
			$nodeset = $xpath->query(implode('', $fields), $this->xml);
			return $nodeset ? $nodeset->item(0) : null;
		}
		catch (Exception $e) {
			throw XmlError::unknown($e);
		}
	}
}
