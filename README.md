U2F Examples
============

Examples of [U2F](https://github.com/ebutleriv/u2f) library in practice. Haphazardly whipped up during HacPhi 2016.

*DO NOT USE FOR REAL* - App stores passwords in plaintext, is probably vulnerable to timing attack, will eventually explode if too many people use it since we don't expire cached requests.

CHANGELOG
---------
* Now prevents challenge reuse/signin replay.
