# Island.is login

Library to make it easier to handle logging in with island.is

To get started with Island.is Identification and Authentication Services (IAS) you'll need to apply: vefur.island.is/innskraningarthjonusta/um/.


## How it works

The token the Ísland.is IAS returns to the service provider(you), for decoding by the service provider, is a digitally signed SAML 2 token encoded in Base 64 and UTF-8.

The SAML message returned by IAS will be digitally signed with a certificate issued by Traustur bunadur. Furthermore, the message will have been transformed with xml-exc-c14n, prior to being digested with SHA256 and signed with a 2048-bit RSA key.

This library helps with validating and verifying the SAML token, and the provided signature.

If you want more information about how this work you can read the technical specification here:
https://vefur.island.is/media/pdf-skjol-a-island.is-2014/island.is-ias-services-instructions.pdf

## Installation

```
composer require stefna/islandis
```

## Usage

### Example usage

```php
<?php
if (isset($_POST['token'])) {
	$authentication = new Islandis\Authenticate(new \Islandis\Verifier('hostname'));
	try {
		$user = $authentication->verify($_POST['token']);
		$kennitala = $user->getKennitala();
		//is authenticated
	} catch (\Islandis\Exception\AuthenticateError $e) {
		echo $e->getMessage();
		//failed  authentication
	}
}
```
