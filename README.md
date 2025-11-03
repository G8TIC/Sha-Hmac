# Sha-Hmac :: Modern SHA256/512 and HMAC-SHA256/512

## Background

I have been using SHA256 and SHA512 in embedded systems they have existed but
always with overly complex reference code, code borrowed from crypto libraries,
or versions found on the internet with questional parentage such as those where
ownership is claimed by Apple or Google.

## Goals and objectives

I decided that for embedded systems I needed my own implementation which:

* uses modern and clean, procedural C11 code
* is designed for standalone use
* is portable across a wide range of systems
* is compiler agnostic
* has simple API calling conventions
* is easy to read, understand and maintain
* includes unit tests against NIST test vectors
* uses a permissive license (in this case MIT)


### Modern and clean C11

Written to be modern and clean code using prodecural C to the C11 standard.

### Standalone operation

Code is complete, in place, and makes no use of libraries or other source.

### Portable

As the code is written in plain prodedural C it should compile and work on a wide range of systems.
To date its been used on 64-bit AMD (x86) and 64-bit ARM.

### Compiler agnostic

While the code was developed using GCC it uses only standard C11 subset so
should work on any C11 compliant compiler.

### Simple APIs

While you can delve in to the innards and do things in parts, in most cases
you just want the single shot function, for example:
```
sha256(uint8_t *out, uint_t *msg, size_t msglen)
```

### Unit tests

Each module includes a test harness with the NIST test vectors.

All four modules can be tested using the unit_tests.sh script.

