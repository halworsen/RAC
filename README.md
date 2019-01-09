# RAC
Randomized Access Control (RAC) is an authentication tool for use with Arduino boards and the RC522 RFID reader.

## Dependencies
* [MFRC522](https://github.com/miguelbalboa/rfid)
* [RFIDUtil](https://github.com/halworsen/rfidutil)
* Entropy

Entropy is avaliable at this [Google Code](https://code.google.com/archive/p/avr-hardware-random-number-generation/downloads) archive.
There's also a [mirror repository](https://github.com/pmjdebruijn/Arduino-Entropy-Library) hosted on GitHub.

## Setting up a tag for use with RAC
To begin using RAC with a tag, you need to set it up first.

Get a tag that has at least one sector with the factory default all 0xFF keys.
Set up an instance of RACAgent with the read and write keys you want to use with the tag.
You don't have to call `init()` if you are only going to perform tag setup.

RAC always assumes that there's a tag present, so select the tag and call `SetupTag()`.
This will set the "key sector" up for use with RAC. The return value indicates success.

Note that a sector set up for use with RAC will have its read and write keys and access bytes changed.
Therefore, you have to use the same read and write keys as when you performed setup when authenticating against the tag,
otherwise RAC can't read the key stored on the tag. You can only authenticate against RAC with the sector you set up for use.

Also note that when you set up a key with RAC, it is set up for the board you used when performing the setup.
You can setup the tag for multiple boards if you set up different sectors of the tag for each board.

## Authenticating with RAC
Assuming you have a tag that is set up for use with RAC on the board you're using, select the tag and call `AuthenticateTag()`.
The return value indicates whether or not the authentication succeeded.

## Security
RAC is intended as a "hobbyist" auth tool, and shouldn't be used for applications where security is a concern.
The idea behind RAC isn't waterproof security, but since the tag gets a new key every time it successfully authenticates,
it defends well enough against tag cloning if the tag is used frequently.

On the flip side, you might get locked out if an attacker clones your tag and uses it before you do!

RAC supports keys that are up to 16 bytes long, but due to MIFARE sector keys only being 6 bytes long
(which provide read access to the block storing the RAC key), you shouldn't expect any security benefits from RAC keys that are longer than 6 bytes.
