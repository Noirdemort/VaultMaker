//
//  main.swift
//  VaultMaker
//
//  Created by Noirdemort on 21/06/20.
//  Copyright © 2020 Noirdemort. All rights reserved.
//

import Foundation
import CryptoSwift

func getPassword() -> String? {
	var buf = [CChar](repeating: 0, count: 16384)
	guard let passphrase = readpassphrase("Enter Master Password: ", &buf, buf.count, 0) else {
		return nil
	}
	
	guard let passphraseStr = String(validatingUTF8: passphrase) else { return nil }
	
	return passphraseStr
}


guard let masterPassword = getPassword() else {
	print("Master Password is required")
	exit(EXIT_FAILURE)
}

print("Enter site url: ")
guard let url = readLine(strippingNewline: true) else {
	print("Site URL can not be empty.")
	exit(EXIT_FAILURE)
}

print("Enter date of birth: ")
guard let dob = readLine(strippingNewline: true) else {
	print("Date of Birth can not be empty.")
	exit(EXIT_FAILURE)
}




let password: Array<UInt8> = Array("\(masterPassword)\(dob)".utf8)
let salt: Array<UInt8> = Array(url.utf8)

do {
	print("[+] Performing key derivation...")

	let key = try PKCS5.PBKDF2(password: password, salt: salt, iterations: 2560, keyLength: 128, variant: .sha512).calculate()
	
	
	print("[+] Performed key derivation.")
	print("[+] Performing SHA-3 hashing...")
	
	var shasum = SHA3(variant: .sha512)
	_ = try shasum.update(withBytes: key)
	let result = try shasum.finish()
	
	print("Password: \(result.toHexString())")
	
} catch {
	print("Some Error Occured.")
	exit(EXIT_FAILURE)
}
