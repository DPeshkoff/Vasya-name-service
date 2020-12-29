#!/usr/bin/python
# -*- coding: UTF-8 -*-

import sys
import argparse
#####################################################################################################
import ecdsa as ec
#####################################################################################################
# Night note to myself: find a way to convert string tp cryptography.hazmat public key
# Currently it raises errors due to hadling as str, not as 
# Until I find a way, I will use ecdsa (because it can convert)
#####################################################################################################
#from cryptography.hazmat.primitives import hashes
#from cryptography.hazmat.primitives.asymmetric import ec
#####################################################################################################
# To delete when fix hazmat
# ec.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP256k1)
#####################################################################################################


# No time for full-on IPFS, so here it is - placeholder
NAMES = {"vasya:bf02633cc12870bd311726b35f4186a3a0c6a771942292de4e6bf3156d494f71e4835fb56c30b21f19630c3169992e9b":"link"}


# Getting Console Parameters
def createParser():
    """createParser:
    Returns: parser
    """

    parser = argparse.ArgumentParser()

    parser.add_argument ('--request_type')
    parser.add_argument ('--uid')
    parser.add_argument ('--ipfs_link')    
    parser.add_argument ('--sig')    

    return parser


# For code clearance - returns if uid is found
def _is_found (uid):
    """_is_found:  
    Required argument: uid 
    Returns: True|False  
    """

    is_found = False
    for i in NAMES:
        if i == uid:
            is_found = True
    return is_found


# Request-type name_service_get
def name_service_get(uid):
    """name_service_get:  
    Required argument: uid 
    Returns: link or error  
    """

    try:
        is_found = _is_found(uid)
        
        if is_found == True:
            return NAMES[uid]
        else:
            return "Error: UserNotFound"
    except:
        return "Error: UnknownError@Get"


# Request-type name_service_get
def name_service_set(uid, link, raw_link): 
    """name_service_get:  
    Required argument: uid, link (signed), raw_link (unsigned)
    Returns: OK or error
    """

    try:
        # get name|key
        name, key = uid.split(":")[0].encode('utf-8'), uid.split(":")[1]

        # CRYTGOGRAPHY.HAZMAT LEGACY
        #key.verify(link, raw_link, ec.ECDSA(hashes.SHA256()))

        # ECDSA TEMPORARY SOLUTION
        verifying_key = ec.VerifyingKey.from_string(bytes.fromhex(key), curve=ec.NIST192p)

        try:
            # Verify signature
            verifying_key.verify(link, raw_link)
        except:
            return "Error: VerificationFailed"
        else:
            NAMES[name.decode('utf-8')] = raw_link.decode('utf-8')
            return "OK: VerificationPassed, LinkUpdated"
    except:
        return "Error: UnknownError@Get"


# Main part of the program - no imports
if __name__ == '__main__':

    # all available modes: record-set, record-get, record-test

    parser = createParser()
    arguments = parser.parse_args(sys.argv[1:])

    request_type = arguments.request_type

    if len(sys.argv) == 1:
        print("Please specify argument (record-set, record-get or record-test)")
        exit(1)

    elif request_type == "record-set":
        name_service_set(arguments.uid, arguments.link, arguments.raw_link)

    elif request_type == "record-get":
        print(name_service_get(arguments.uid))

    elif request_type == "record-test":

        # CRYTGOGRAPHY.HAZMAT LEGACY
        #test_private_key = ec.generate_private_key(ec.SECP384R1())
        #test_public_key = test_private_key.public_key()
        #test_raw_link = "iamatestlink".encode('utf8')
        #test_link = test_private_key.sign(bytes(test_raw_link), ec.ECDSA(hashes.SHA256()))
        #test_uid = "TestSubject01:" + str(test_public_key)

        # ECDSA TEMPORARY SOLUTION

        # Generating test keys
        test_signing_key = ec.SigningKey.generate(curve=ec.NIST192p)
        test_verifying_key = test_signing_key.get_verifying_key()

        # Generating test link and signing it
        test_raw_link = b"testlinktestlinktestlinktestlinktestlinktestlink"
        test_link = test_signing_key.sign(test_raw_link)

        # Our test UID
        test_uid = "TestSubject01:" + test_verifying_key.to_string().hex()

        # Print base info
        print("UID: ", test_uid)
        print("Signing key: ", test_signing_key.to_string().hex())
        print("Verifying key: ", test_verifying_key.to_string().hex())

        # Test 1: Check signature - should be True
        print("Check signature: ", test_verifying_key.verify(test_link, test_raw_link))

        # Test 2: Get not existing user - should be True
        print("Getting not existing user: gets 'Error: UserNotFound'? ", name_service_get(test_uid) == "Error: UserNotFound")

        # Test 3: Set new user - should be True
        print("Setting up new user: gets 'OK: VerificationPassed, LinkUpdated'? ", name_service_set(test_uid, test_link, test_raw_link) == "OK: VerificationPassed, LinkUpdated")

        # Test 4: Check link - should be True
        print("Getting existing user: assert equal raw_link and get-link: ", name_service_get(test_uid) == test_raw_link.decode("utf-8"))    

        # Create false identity to test handling wrong signatures 
        false_test_signing_key = ec.SigningKey.generate(curve=ec.NIST192p)
        false_test_verifying_key = test_signing_key.get_verifying_key()

        # Create false UID
        false_test_uid = "TestSubject01:" + false_test_verifying_key.to_string().hex()

        # Create false link for testing
        false_test_raw_link = b"falsetestlinkfalsetestlinkfalsetestlinkfalsetest"
        false_test_link = false_test_signing_key.sign(false_test_raw_link)

        # Test 5: Try to update user with wrong signature - should be True
        print("Updating user with wrong signature: gets 'Error: VerificationFailed'? ", name_service_set(false_test_uid, false_test_link, false_test_raw_link) == "Error: VerificationFailed")

        # Test 6: Check if link is not modified - should be True
        print("Check link in the system: assert raw_link and get-link: ", name_service_get(test_uid) == test_raw_link.decode("utf-8"))  

        # New link for test 7
        new_test_raw_link = b"newlinknewlinknewlinknewlinknewlinknewlinknewlik"
        new_test_link = test_signing_key.sign(new_test_raw_link)

        # Test 7: Update user with right signature - should be True
        print("Updating user with right signature: gets 'OK: VerificationPassed, LinkUpdated'? ", name_service_set(test_uid, new_test_link, new_test_raw_link) == "OK: VerificationPassed, LinkUpdated")

        # Test 8: Check if link is not modified - should be False
        print("Check link in the system: assert raw_link and get-link (should be False!): ", name_service_get(test_uid) == test_raw_link.decode("utf-8"))  

        # Test 9: Check if link IS modified - should be True
        print("Check link in the system: assert new_raw_link and get-link: ", name_service_get(test_uid) == new_test_raw_link.decode("utf-8"))  

    else:
        print("Please specify argument (record-set, record-get or record-test)")