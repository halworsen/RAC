/*
	RAC.cpp
*/

#include "RAC.h"
#include <MFRC522.h>
#include <RFIDUtil.h>
#include <EEPROM.h>
#include <Entropy.h>

#define BLOCKS_PER_SECTOR 4 // a mifare classic has 4 blocks per sector
#define BYTES_IN_BLOCK 16 // 16 bytes/block
#define SECTOR_KEY_LENGTH 6 // a sector key is 6 bytes long

void RACAgent::init(){
	// init entropy and generate a standby key
	Entropy.initialize();
	GenStandbyKey();

	// fetch the keys from the EEPROM
	byte value;
	RACKey current_key;
	bool is_factory_default = true;

	for(int address = 0; address < EEPROM_SPACE; address+=KEY_LENGTH){
		for(int offset = 0; offset < KEY_LENGTH; offset++){
			value = EEPROM.read(address+offset);

			if(value != 0xFF)
				is_factory_default = false;

			current_key.key_bytes[offset] = value;
		}

		// extra byte to indicate if the key is valid for key tests
		current_key.key_bytes[KEY_LENGTH] = is_factory_default ? 0x00 : 0x01;
		stored_keys[address/KEY_LENGTH] = current_key;

		is_factory_default = true;
	}
}

/*
	Attempts to authenticate a tag and returns whether or not the tag is valid
*/
bool RACAgent::AuthenticateTag(){
	// attempt to get the key from the tag
	if(!FetchKey())
		return false;

	// check if the tag's key is valid
	if(!TestKey(current_key))
		return false;

	// attempt to make a new key for the tag and write to it
	if(!UpdateTagKey(valid_index))
		return false;

	return true;
}

/*
	Sets up the tag for use with RAC on this board
*/
bool RACAgent::SetupTag(){
	int free_slot = GetFreeKeySlot();

	if(free_slot == -1)
		return false;

	if(!SetupTagSector())
		return false;

	return UpdateTagKey(free_slot);
}

/*
	Sets a factory default sector up for use with RAC
	Meaning it sets the read/write keys and access bits
*/
bool RACAgent::SetupTagSector(){
	byte trailer_block = ((key_sector+1) * 4) - 1;
	// these access bytes gives the access bits 0 1 1 for the sector trailer
	// and 1 0 0 for all of the data blocks
	byte access_bytes[4] = {0x78, 0x77, 0x88, 0x00};
	MFRC522::MIFARE_Key factory_key;
	byte new_trailer[16];
	bool succ;

	for(int i = 0; i < SECTOR_KEY_LENGTH; i++){
		factory_key.keyByte[i] = 0xFF;
	}
  
	// access keys
	for(int i = 0; i < SECTOR_KEY_LENGTH; i++){
		new_trailer[i] = read_key->keyByte[i];
		new_trailer[i+10] = write_key->keyByte[i];
	}

	// access bytes
	for(int i = SECTOR_KEY_LENGTH; i < SECTOR_KEY_LENGTH+4; i++){
		new_trailer[i] = access_bytes[i-SECTOR_KEY_LENGTH];
	}

	succ = util.WriteBlock(trailer_block, &(new_trailer[0]), BYTES_IN_BLOCK, &factory_key);
	if(!succ)
		return false;

	return true;
}

/*
	Retrieves the key stored in the tag and stores it as the current key
*/
bool RACAgent::FetchKey(){
	byte key_block = key_sector*BLOCKS_PER_SECTOR;
	byte block_data[BYTES_IN_BLOCK+1] = {0x00};

	util.ReadBlock(key_block, block_data, read_key);

	for(int i = 0; i < KEY_LENGTH; i++){
		current_key.key_bytes[i] = block_data[i];
	}

	return (block_data[BYTES_IN_BLOCK] == 0x01);
}

/*
	Tests the key against the valid keys to see if the passed key is valid
*/
bool RACAgent::TestKey(RACKey key){
	for(int i = 0; i < AMOUNT_STORED_KEYS; i++){
		if(!IsKeyValid(stored_keys[i]))
			continue;

		if(KeysEqual(key, stored_keys[i])){
			valid_index = i;
			return true;
		}
	}

	return false;
}


/*
	Updates the tag with a new key and write it to EEPROM
*/
bool RACAgent::UpdateTagKey(int old_key_index){
	// sanity
	if(old_key_index == -1)
		return false;

	byte key_block = key_sector*BLOCKS_PER_SECTOR;
	RACKey new_key = GetNewKey();

	// get a unique key
	while(!IsKeyUnique(new_key)){
		new_key = GetNewKey();
	}

	// the new key block, padded with 0x00
	byte block_bytes[BYTES_IN_BLOCK] = {0x00};
	for(int i = 0; i < KEY_LENGTH; i++){
		block_bytes[i] = new_key.key_bytes[i];
	}

	// write the new key to the tag
	bool succ = util.WriteBlock(key_block, &(block_bytes[0]), BYTES_IN_BLOCK, write_key);
	if(!succ){
		return false;
	}

	// overwrite old key in EEPROM
	int address = old_key_index*KEY_LENGTH;
	for(int i = 0; i < KEY_LENGTH; i++){
		EEPROM.write(address+i, new_key.key_bytes[i]);
	}

	// put the new key in the stored keys array
	stored_keys[old_key_index] = new_key;

	return true;
}

/*
	Utility. Returns the standby key and generates a new one
*/
RACAgent::RACKey RACAgent::GetNewKey(){
	RACKey old_key = standby_key;

	// generate a new standby key
	GenStandbyKey();

	return old_key;
}

/*
	Utility. Generates a new standby key
*/
void RACAgent::GenStandbyKey(){
	// count the amount of 0xFF in the new key
	// this is accounting for the insanely slim chance that the random key is all 0xFF, which is invalid
	byte bad_count = 0;

	do{
		for(int i = 0; i < KEY_LENGTH; i++){
			byte random = Entropy.randomByte();
			if(random == 0xFF)
				bad_count++;

			standby_key.key_bytes[i] = random;
		}
	}while(bad_count == KEY_LENGTH);

	standby_key.key_bytes[KEY_LENGTH] = 0x01;
}

/*
	Utility. Returns the index in stored_keys for a free key slot (or -1 if none are available)
*/
int RACAgent::GetFreeKeySlot(){
	for(int i = 0; i < AMOUNT_STORED_KEYS; i++){
		if(!IsKeyValid(stored_keys[i]))
			return i;
	}

	return -1;
}

/*
	Utility. Checks if a given key is unique among the currently stored keys
*/
bool RACAgent::IsKeyUnique(RACKey key){
	return !TestKey(key);
}

/*
	Utility. Checks if a given key is valid, i.e. not factory default
*/
bool RACAgent::IsKeyValid(RACKey key){
	return (key.key_bytes[KEY_LENGTH] == 0x01);
}

/*
	Utility. Checks if two keys have the exact same bytes
*/
bool RACAgent::KeysEqual(RACKey key, RACKey other_key){
	// compare each byte
	for(int j = 0; j < KEY_LENGTH; j++){
		if(key.key_bytes[j] != other_key.key_bytes[j])
			break;
		// made it to the last iteration without any byte mismatches, so the keys are equal
		if(j == KEY_LENGTH-1)
			return true;
	}

	return false;
}