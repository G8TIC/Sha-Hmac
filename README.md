# Sha-Hmac :: Modern implementations of SHA256/512 and HMAC-SHA256/512

I have been using SHA256 and SHA512 in communications protocols on embedded
systems in C since they have existed but always with overly complex reference
code, code stolen from crypto libraries, or versions found on the internet
with questional parentage such as those where ownership is claimed by Apple
or Google.

I decided that for embedded systems I needed my own implementation which:

* modern and clean code
* written in procedural C compatible with C11
* designed for standalone use
* portable across a wide range of systems
* compiler agnostic
* simple API calling conventions
* easy to read, understand and maintain
* provided with unit tests against NIST test vectors


## Modern and clean 

Modern and clean code to the C11 standard.


## Standalone operation

Code is complete, in place, and makes no use of libraries or other source.

## Portable

As the code is written in plain prodedural C (C11) it should compile and
work on a wide range of systems.
To date its been used on 64-bit AMD (x86) and 64-bit ARM.

## Compiler agnostic

While the code was developed using GCC it uses only standard C11 subset so
should work on any C11 compliant compiler.

## Simple APIs

While you can delve in to the innards and do things in parts, in most cases
you just want the single shot function, for example:

sha256(uint8_t *out, uintt_t *msg, size_t msglen)

## Unit tests

Each module includes a test harness with the NIST test vectors.

All four mobiles can be tested using the unit_tests.sh script.


