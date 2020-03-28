/*
Android keystore hooks + utilities

All instances of keystore are captured by hooking any getInstance() calls. 
You can find them in keystoreList variable.

Utilities:

KeystoreListAllAliases()
ListAliasesStatic()
* List all aliases in keystores of known hardcoded types(in keystoreTypes)

KeystoreListAllAliasesOnAllInstances()
ListAliasesRuntime()
* List all aliases in keystores of all instances obtained during app runtime.
* Instances that will be dumped are collected via hijacking
* Keystore.getInstance() -> hookKeystoreGetInstance()

ListAliasesAndroid()
* List all aliases in AndroidKeyStore.

ListAliasesType(String type)
* List all aliases in a keystore of given 'type'.
* Example: ListAliasesType('AndroidKeyStore');

ListAliasesObj(Object obj)
* List all aliases for a given keystore object. 
* Example: ListAliasesObj(keystoreObj);

GetKeyStore(String name)
* Retrieve keystore instance from keystoreList.
* Example: GetKeyStore("KeyStore...@af102a");

AliasInfo(String alias)
* List keystore key properties in a JSON object.
* Example: AliasInfo('secret');

*/


Java.perform(function () {
	hookKeystoreGetInstance();
	hookKeystoreGetInstance_Provider();
	hookKeystoreGetInstance_Provider2();
	hookKeystoreConstructor();
	hookKeystoreLoad(false);
	hookKeystoreLoadStream(false);
	hookKeystoreGetKey();
	hookKeystoreSetKeyEntry();
	//hookKeystoreGetCertificate();
	hookKeystoreGetCertificateChain();
	hookKeystoreGetEntry();
	hookKeystoreSetEntry();
	hookKeystoreSetKeyEntry();
	hookKeystoreSetKeyEntry2();
	hookKeystoreStore();
	hookKeystoreStoreStream()


});
console.log("KeyStore hooks loaded!");

var keystoreList = [];
var StringCls = null;
Java.perform(function () {
	StringCls = Java.use('java.lang.String');


});

function hookKeystoreConstructor() {
	var keyStoreConstructor = Java.use('java.security.KeyStore').$init.overload("java.security.KeyStoreSpi", "java.security.Provider", "java.lang.String");
	keyStoreConstructor.implementation = function (keyStoreSpi, provider, type) {
		//console.log("[Call] Keystore(java.security.KeyStoreSpi, java.security.Provider, java.lang.String )")
		console.log("[Keystore()]: KeyStoreSpi: " + keyStoreSpi + ", Provider: " + provider + ", type: " + type);
		return this.$init(keyStoreSpi, provider, type);

	}
}

function hookKeystoreGetInstance() {
	var keyStoreGetInstance = Java.use('java.security.KeyStore')['getInstance'].overload("java.lang.String");
	keyStoreGetInstance.implementation = function (type) {
		//console.log("[Call] Keystore.getInstance(java.lang.String )")
		console.log("[Keystore.getInstance()]: type: " + type);
		var tmp = this.getInstance(type);
		keystoreList.push(tmp); // Collect keystore objects to allow dump them later using ListAliasesRuntime()
		return tmp;
	}
}

function hookKeystoreGetInstance_Provider() {
	var keyStoreGetInstance = Java.use('java.security.KeyStore')['getInstance'].overload("java.lang.String", "java.lang.String");
	keyStoreGetInstance.implementation = function (type, provider) {
		//console.log("[Call] Keystore.getInstance(java.lang.String, java.lang.String )")
		console.log("[Keystore.getInstance2()]: type: " + type + ", provider: " + provider);
		var tmp = this.getInstance(type, proivder);
		keystoreList.push(tmp); // Collect keystore objects to allow dump them later using ListAliasesRuntime()
		return tmp;
	}
}

function hookKeystoreGetInstance_Provider2() {
	var keyStoreGetInstance = Java.use('java.security.KeyStore')['getInstance'].overload("java.lang.String", "java.security.Provider");
	keyStoreGetInstance.implementation = function (type, provider) {
		//console.log("[Call] Keystore.getInstance(java.lang.String, java.security.Provider )")
		console.log("[Keystore.getInstance2()]: type: " + type + ", provider: " + provider);
		var tmp = this.getInstance(type, proivder);
		keystoreList.push(tmp); // Collect keystore objects to allow dump them later using ListAliasesRuntime()
		return tmp;
	}
}

/*
* Hook Keystore.load( ... ), set dump to true if you want to perform dump of available Aliases automatically.	
*/
function hookKeystoreLoad(dump) {
	var keyStoreLoad = Java.use('java.security.KeyStore')['load'].overload('java.security.KeyStore$LoadStoreParameter');
	/* following function hooks to a Keystore.load(java.security.KeyStore.LoadStoreParameter) */
	keyStoreLoad.implementation = function (param) {
		//console.log("[Call] Keystore.load(java.security.KeyStore.LoadStoreParameter)")
		console.log("[Keystore.load(LoadStoreParameter)]: keystoreType: " + this.getType() + ", param: " + param);
		this.load(param);
		if (dump) console.log(" Keystore loaded aliases: " + ListAliasesObj(this));
	}
}

/*
* Hook Keystore.load( ... ), set dump to true if you want to perform dump of available Aliases automatically.	
*/
function hookKeystoreLoadStream(dump) {
	var keyStoreLoadStream = Java.use('java.security.KeyStore')['load'].overload('java.io.InputStream', '[C');
	/* following function hooks to a Keystore.load(InputStream stream, char[] password) */
	keyStoreLoadStream.implementation = function (stream, charArray) {
		//console.log("[Call] Keystore.load(InputStream stream, char[] password)")
		//var hexString = readStreamToHex (stream);
		console.log("[Keystore.load(InputStream, char[])]: keystoreType: " + this.getType() + ", password: '" + charArrayToString(charArray) + "', inputSteam: " + stream);
		this.load(stream, charArray);
		if (dump) console.log(" Keystore loaded aliases: " + ListAliasesObj(this));
	}
}

function hookKeystoreStore() {
	var keyStoreStoreStream = Java.use('java.security.KeyStore')['store'].overload('java.security.KeyStore$LoadStoreParameter');
	/* following function hooks to a Keystore.store(java.security.KeyStore$LoadStoreParameter) */
	keyStoreStoreStream.implementation = function (param) {
		console.log("[Keystore.store()]: keystoreType: " + this.getType() + ", param: '" + param);
		this.store(stream, charArray);
	}
}

function hookKeystoreStoreStream() {
	var keyStoreStoreStream = Java.use('java.security.KeyStore')['store'].overload('java.io.OutputStream', '[C');
	/* following function hooks to a Keystore.store(OutputStream stream, char[] password) */
	keyStoreStoreStream.implementation = function (stream, charArray) {
		console.log("[Keystore.store(OutputStream, char[])]: keystoreType: " + this.getType() + ", password: '" + charArrayToString(charArray) + "', outputSteam: " + stream);
		this.store(stream, charArray);
	}
}

function hookKeystoreGetKey() {
	var keyStoreGetKey = Java.use('java.security.KeyStore')['getKey'].overload("java.lang.String", "[C");
	keyStoreGetKey.implementation = function (alias, charArray) {
		//console.log("[Call] Keystore.getKey(java.lang.String, [C )")
		console.log("[Keystore.getKey()]: alias: " + alias + ", password: '" + charArrayToString(charArray) + "'");
		return this.getKey(alias, charArray);
	}
}

function hookKeystoreSetEntry() {
	var keyStoreSetKeyEntry = Java.use('java.security.KeyStore')['setEntry'].overload("java.lang.String", "java.security.KeyStore$Entry", "java.security.KeyStore$ProtectionParameter");
	keyStoreSetKeyEntry.implementation = function (alias, entry, protection) {
		//console.log("[Call] Keystore.setEntry(java.lang.String, java.security.KeyStore$Entry, java.security.KeyStore$ProtectionParameter )")
		console.log("[Keystore.setEntry()]: alias: " + alias + ", entry: " + dumpKeyStoreEntry(entry) + "', protection: " + dumpProtectionParameter(protection));
		return this.setEntry(alias, entry, protection);
	}
}

function hookKeystoreSetKeyEntry() {
	var keyStoreSetKeyEntry = Java.use('java.security.KeyStore')['setKeyEntry'].overload("java.lang.String", "java.security.Key", "[C", "[Ljava.security.cert.Certificate;");
	keyStoreSetKeyEntry.implementation = function (alias, key, charArray, certs) {
		//console.log("[Call] Keystore.setKeyEntry(java.lang.String, java.security.Key, [C, [Ljava.security.cert.Certificate; )
		console.log("[Keystore.setKeyEntry()]: alias: " + alias + ", key: " + key + ", password: '" + charArrayToString(charArray) + "', certs: " + certs);
		return this.setKeyEntry(alias, key, charArray, certs);
	}
}

function hookKeystoreSetKeyEntry2() {
	var keyStoreSetKeyEntry = Java.use('java.security.KeyStore')['setKeyEntry'].overload("java.lang.String", "[B", "[Ljava.security.cert.Certificate;");
	keyStoreSetKeyEntry.implementation = function (alias, key, certs) {
		//console.log("[Call] Keystore.setKeyEntry(java.lang.String, [B, [Ljava.security.cert.Certificate; )")
		console.log("[Keystore.setKeyEntry2()]: alias: " + alias + ", key: " + key + "', certs: " + certs);
		return this.setKeyEntry(alias, key, certs);
	}
}

/*
* Usually used to load certs for cert pinning.
*/
function hookKeystoreGetCertificate() {
	var keyStoreGetCertificate = Java.use('java.security.KeyStore')['getCertificate'].overload("java.lang.String");
	keyStoreGetCertificate.implementation = function (alias) {
		//console.log("[Call] Keystore.getCertificate(java.lang.String )")
		console.log("[Keystore.getCertificate()]: alias: " + alias);
		return this.getCertificate(alias);
	}
}

/*
* Usually used to load certs for cert pinning.
*/
function hookKeystoreGetCertificateChain() {
	var keyStoreGetCertificate = Java.use('java.security.KeyStore')['getCertificateChain'].overload("java.lang.String");
	keyStoreGetCertificate.implementation = function (alias) {
		//console.log("[Call] Keystore.getCertificateChain(java.lang.String )")
		console.log("[Keystore.getCertificateChain()]: alias: " + alias);
		return this.getCertificateChain(alias);
	}
}

function hookKeystoreGetEntry() {
	var keyStoreGetEntry = Java.use('java.security.KeyStore')['getEntry'].overload("java.lang.String", "java.security.KeyStore$ProtectionParameter");
	keyStoreGetEntry.implementation = function (alias, protection) {
		//console.log("[Call] Keystore.getEntry(java.lang.String, java.security.KeyStore$ProtectionParameter )")
		console.log("[Keystore.getEntry()]: alias: " + alias + ", protection: '" + dumpProtectionParameter(protection) + "'");
		var entry = this.getEntry(alias, protection);
		console.log("[getEntry()]: Entry: " + dumpKeyStoreEntry(entry));
		return entry;
	}
}

function dumpProtectionParameter(protection) {
	if (protection != null) {
		// android.security.keystore.KeyProtection, java.security.KeyStore.CallbackHandlerProtection, java.security.KeyStore.PasswordProtection, android.security.KeyStoreParameter 
		var protectionCls = protection.$className;
		if (protectionCls.localeCompare("android.security.keystore.KeyProtection") == 0) {
			return "" + protectionCls + " [implement dumping if needed]";
		}
		else if (protectionCls.localeCompare("java.security.KeyStore.CallbackHandlerProtection") == 0) {
			return "" + protectionCls + " [implement dumping if needed]";
		}
		else if (protectionCls.localeCompare("java.security.KeyStore.PasswordProtection") == 0) {
			getPasswordMethod = Java.use('java.security.KeyStore.PasswordProtection')['getPassword'];
			password = getPasswordMethod.call(protection);
			return "password: " + charArrayToString(password);
		}
		else if (protectionCls.localeCompare("android.security.KeyStoreParameter") == 0) {
			isEncryptionRequiredMethod = Java.use('android.security.KeyStoreParameter')['isEncryptionRequired'];
			result = isEncryptionRequiredMethod.call(protection);
			return "isEncryptionRequired: " + result;
		}
		else
			return "Unknown protection parameter type: " + protectionCls;
	}
	else
		return "null";

}

function dumpKeyStoreEntry(entry) {
	// java.security.KeyStore$PrivateKeyEntry, java.security.KeyStore$SecretKeyEntry, java.security.KeyStore$TrustedCertificateEntry, android.security.WrappedKeyEntry 
	if (entry != null) {
		var entryCls = entry.$className;
		var castedEntry = Java.cast(entry, Java.use(entryCls));
		if (entryCls.localeCompare("java.security.KeyStore$PrivateKeyEntry") == 0) {
			var getPrivateKeyEntryMethod = Java.use('java.security.KeyStore$PrivateKeyEntry')['getPrivateKey'];
			var key = getPrivateKeyEntryMethod.call(castedEntry);

			return "" + entryCls + " [implement key dumping if needed] " + key.$className;
		}
		else if (entryCls.localeCompare("java.security.KeyStore$SecretKeyEntry") == 0) {
			var getSecretKeyMethod = Java.use('java.security.KeyStore$SecretKeyEntry')['getSecretKey'];
			var key = getSecretKeyMethod.call(castedEntry);
			var keyGetFormatMethod = Java.use(key.$className)['getFormat'];
			var keyGetEncodedMethod = Java.use(key.$className)['getEncoded'];
			//console.log(""+key.$className);
			if (key.$className.localeCompare("android.security.keystore.AndroidKeyStoreSecretKey") == 0)
				return "keyClass: android.security.keystore.AndroidKeyStoreSecretKey can't dump";
			return "keyFormat: " + keyGetFormatMethod.call(key) + ", encodedKey: '" + keyGetEncodedMethod.call(key) + "', key: " + key;
		}
		else if (entryCls.localeCompare("java.security.KeyStore$TrustedCertificateEntry") == 0) {
			return "" + entryCls + " [implement key dumping if needed]";
		}
		else if (entryCls.localeCompare("android.security.WrappedKeyEntry") == 0) {
			return "" + entryCls + " [implement key dumping if needed]";
		}
		else
			return "Unknown key entry type: " + entryCls;
	}
	else
		return "null";
}

/*
* Dump all aliasses in keystores of all types(predefined in keystoreTypes)	
*/
function ListAliasesStatic() {
	// BCPKCS12/PKCS12-DEF - exceptions
	var keystoreTypes = ["AndroidKeyStore", "AndroidCAStore", /*"BCPKCS12",*/ "BKS", "BouncyCastle", "PKCS12", /*"PKCS12-DEF"*/];
	keystoreTypes.forEach(function (entry) {
		console.log("[ListAliasesStatic] keystoreType: " + entry + " \nAliases: " + ListAliasesType(entry));
	});
	return "[done]";
}

/*
* Dump all aliasses in keystores of all instances obtained during app runtime. 
* Instances that will be dumped are collected via hijacking Keystre.getInstance() -> hookKeystoreGetInstance()
*/
function ListAliasesRuntime() {
	Java.perform(function () {
		console.log("[ListAliasesRuntime] Instances: " + keystoreList);
		keystoreList.forEach(function (entry) {
			console.log("[ListAliasesRuntime] keystoreObj: " + entry + " type: " + entry.getType() + " \n" + ListAliasesObj(entry));
		});
	});
	return "[done]";
}

/*
* Dump all aliasses in AndroidKey keystore. 
*/
function ListAliasesAndroid() {
	return ListAliasesType("AndroidKeyStore");
}

/*
* Dump all aliasses in keystore of given 'type'. 
* Example: ListAliasesType('AndroidKeyStore');
*/
function ListAliasesType(type) {
	var result = [];
	Java.perform(function () {
		var keyStoreCls = Java.use('java.security.KeyStore');
		var keyStoreObj = keyStoreCls.getInstance(type);
		keyStoreObj.load(null);
		var aliases = keyStoreObj.aliases();
		//console.log("aliases: " + aliases.getClass());
		while (aliases.hasMoreElements()) {
			result.push("'" + aliases.nextElement() + "'");
		}
	});
	return result;
}

/*
* Dump all aliasses for a given keystore object. 
* Example: ListAliasesObj(keystoreObj);
*/
function ListAliasesObj(obj) {
	var result = [];
	Java.perform(function () {
		var aliases = obj.aliases();
		while (aliases.hasMoreElements()) {
			result.push(aliases.nextElement() + "");
		}
	});
	return result;
}

/*
* Retrieve keystore instance from keystoreList
* Example: GetKeyStore("KeyStore...@af102a");
*/
function GetKeyStore(keystoreName) {
	var result = null;
	Java.perform(function () {
		for (var i = 0; i < keystoreList.length; i++) {
			if (keystoreName.localeCompare("" + keystoreList[i]) == 0)
				result = keystoreList[i];
		}
	});
	return result;
}

/*
* Dump keystore key properties in JSON object
* Example: AliasInfo('secret');
*/
function AliasInfo(keyAlias) {
	var result = {};
	Java.perform(function () {
		var keyStoreCls = Java.use('java.security.KeyStore');
		var keyFactoryCls = Java.use('java.security.KeyFactory');
		var keyInfoCls = Java.use('android.security.keystore.KeyInfo');
		var keySecretKeyFactoryCls = Java.use('javax.crypto.SecretKeyFactory');
		var keyFactoryObj = null;

		var keyStoreObj = keyStoreCls.getInstance('AndroidKeyStore');
		keyStoreObj.load(null);
		var key = keyStoreObj.getKey(keyAlias, null);
		if (key == null) {
			console.log('key does not exist');
			return null;
		}
		try {
			keyFactoryObj = keyFactoryCls.getInstance(key.getAlgorithm(), 'AndroidKeyStore');
		} catch (err) {
			keyFactoryObj = keySecretKeyFactoryCls.getInstance(key.getAlgorithm(), 'AndroidKeyStore');
		}
		var keyInfo = keyFactoryObj.getKeySpec(key, keyInfoCls.class);
		result.keyAlgorithm = key.getAlgorithm();
		result.keySize = keyInfoCls['getKeySize'].call(keyInfo);
		result.blockModes = keyInfoCls['getBlockModes'].call(keyInfo);
		result.digests = keyInfoCls['getDigests'].call(keyInfo);
		result.encryptionPaddings = keyInfoCls['getEncryptionPaddings'].call(keyInfo);
		result.keyValidityForConsumptionEnd = keyInfoCls['getKeyValidityForConsumptionEnd'].call(keyInfo);
		if (result.keyValidityForConsumptionEnd != null) result.keyValidityForConsumptionEnd = result.keyValidityForConsumptionEnd.toString();
		result.keyValidityForOriginationEnd = keyInfoCls['getKeyValidityForOriginationEnd'].call(keyInfo);
		if (result.keyValidityForOriginationEnd != null) result.keyValidityForOriginationEnd = result.keyValidityForOriginationEnd.toString();
		result.keyValidityStart = keyInfoCls['getKeyValidityStart'].call(keyInfo);
		if (result.keyValidityStart != null) result.keyValidityStart = result.keyValidityStart.toString();
		result.keystoreAlias = keyInfoCls['getKeystoreAlias'].call(keyInfo);
		result.origin = keyInfoCls['getOrigin'].call(keyInfo);
		result.purposes = keyInfoCls['getPurposes'].call(keyInfo);
		result.signaturePaddings = keyInfoCls['getSignaturePaddings'].call(keyInfo);
		result.userAuthenticationValidityDurationSeconds = keyInfoCls['getUserAuthenticationValidityDurationSeconds'].call(keyInfo);
		result.isInsideSecureHardware = keyInfoCls['isInsideSecureHardware'].call(keyInfo);
		result.isInvalidatedByBiometricEnrollment = keyInfoCls['isInvalidatedByBiometricEnrollment'].call(keyInfo);
		try { result.isTrustedUserPresenceRequired = keyInfoCls['isTrustedUserPresenceRequired'].call(keyInfo); } catch (err) { }
		result.isUserAuthenticationRequired = keyInfoCls['isUserAuthenticationRequired'].call(keyInfo);
		result.isUserAuthenticationRequirementEnforcedBySecureHardware = keyInfoCls['isUserAuthenticationRequirementEnforcedBySecureHardware'].call(keyInfo);
		result.isUserAuthenticationValidWhileOnBody = keyInfoCls['isUserAuthenticationValidWhileOnBody'].call(keyInfo);
		try { result.isUserConfirmationRequired = keyInfoCls['isUserConfirmationRequired'].call(keyInfo); } catch (err) { }
		//console.log(" result: " + JSON.stringify(result));

		//console.log("aliases: " + aliases.getClass());


	});
	return result;
}

/* following function reads an InputStream and returns an ASCII char representation of it */
function readStreamToHex(stream) {
	var data = [];
	var byteRead = stream.read();
	while (byteRead != -1) {
		data.push(('0' + (byteRead & 0xFF).toString(16)).slice(-2));
		/* <---------------- binary to hex ---------------> */
		byteRead = stream.read();
	}
	stream.close();
	return data.join('');
}

function charArrayToString(charArray) {
	if (charArray == null)
		return '(null)';
	else
		return StringCls.$new(charArray);
}
