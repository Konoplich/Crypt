#!/bin/bash

rm ./t

gcc crypt_v5.c -o t -L. -lcrypt -Wl,-rpath,.
