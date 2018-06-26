/*
	RAC.h
*/

#ifndef RAC_h
#define RAC_h

#include <Arduino.h>
#include <MFRC522.h>
#include <RFIDUtil.h>

#define KEY_LENGTH 8 // we'll use the first 8 bytes of a SHA-256 hash, so each key is 8 bytes long
#define EEPROM_SPACE 64 // we use 64 bytes of EEPROM storage
#define AMOUNT_STORED_KEYS EEPROM_SPACE/KEY_LENGTH

class RACAgent{
public:
	typedef struct{
		byte key_bytes[KEY_LENGTH+1]; // the extra byte is to indicate if the key is a factory default (which is never accepted)
	} RACKey;

	RACAgent(RFIDUtil _util, byte _key_sector, MFRC522::MIFARE_Key *_read_key, MFRC522::MIFARE_Key *_write_key) :
		util(_util),
		key_sector(_key_sector),
		read_key(_read_key),
		write_key(_write_key) {};

	void init();

	bool AuthenticateTag();
	bool SetupTag();
private:
	const RFIDUtil util;
	const byte key_sector;

	const MFRC522::MIFARE_Key *read_key;
	const MFRC522::MIFARE_Key *write_key;

	RACKey stored_keys[AMOUNT_STORED_KEYS];
	RACKey current_key;
	int valid_index = -1; // index in stored_keys of the key that matches current_key
	RACKey standby_key; // entropy needs time to generate new bits (32bits/s) so keep one ready at all times

	// for setting up tags
	bool SetupTagSector();

	// protocol related
	bool FetchKey(); // fetches the tag key into current_key
	bool TestKey(RACKey key); // checks if a key is valid
	bool UpdateTagKey(int old_key_index); // update the key on the tag with the standby key

	// utility
	void GenStandbyKey();
	RACKey GetNewKey(); // get the standby key and make a new one
	int GetFreeKeySlot();
	bool IsKeyUnique(RACKey key);
	bool IsKeyValid(RACKey key);
	bool KeysEqual(RACKey key, RACKey other_key);
};

#endif