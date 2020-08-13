#!/bin/sh
#20200204

version="`cat version`"

if [ x"`uname -s`" != "xDarwin" ]; then
  apt-get -qq update 1>/dev/null 2>/dev/null || { echo "apt-get update: failed"; exit 111; }
  apt-get -qqy install build-essential clang rsync xsltproc libssl-dev 1>/dev/null 2>/dev/null || { echo "apt-get install: failed"; exit 111; }
fi

shorthostname=`hostname | sed 's/\..*//' | tr -cd '[a-z][A-Z][0-9]' | tr '[A-Z]' '[a-z]'`

rsync -a mj/ "supercop-${version}/"
cd "supercop-${version}"

(
  if [ x"${JOBRUNNER_ARCH}" = xarmhf ]; then
    echo 'gcc -O3 -fwrapv -march=armv7-a -mfloat-abi=hard -mfpu=neon -fomit-frame-pointer'
    echo 'gcc -Os -fwrapv -march=armv7-a -mfloat-abi=hard -mfpu=neon -fomit-frame-pointer'
    #echo 'clang -O3 -fwrapv -march=armv7-a -mfloat-abi=hard -mfpu=neon -fomit-frame-pointer'
    echo 'gcc -O3 -fomit-frame-pointer -fwrapv -fPIC -fPIE'
    echo 'gcc -Os -fomit-frame-pointer -fwrapv -fPIC -fPIE'
  else
    #echo 'gcc -march=native -mtune=native -O3 -fomit-frame-pointer -fwrapv -fPIC -fPIE'
    #echo 'clang -march=native -mtune=native -O3 -fomit-frame-pointer -fwrapv -fPIC -fPIE'
    #echo 'gcc -march=native -mtune=native -Os -fomit-frame-pointer -fwrapv -fPIC -fPIE'
    #echo 'clang -march=native -mtune=native -Os -fomit-frame-pointer -fwrapv -fPIC -fPIE'
    #echo 'gcc -march=native -mtune=native -O2 -fomit-frame-pointer -fwrapv -fPIC -fPIE'
    #echo 'clang -march=native -mtune=native -O2 -fomit-frame-pointer -fwrapv -fPIC -fPIE'
    #echo 'gcc -march=native -mtune=native -O -fomit-frame-pointer -fwrapv -fPIC -fPIE'
    #echo 'clang -march=native -mtune=native -O -fomit-frame-pointer -fwrapv -fPIC -fPIE'
    echo 'gcc -O3 -fomit-frame-pointer -fwrapv -fPIC -fPIE'
    echo 'clang -O3 -fomit-frame-pointer -fwrapv -fPIC -fPIE'
    #echo 'gcc -Os -fomit-frame-pointer -fwrapv -fPIC -fPIE -maes'
    #echo 'clang -Os -fomit-frame-pointer -fwrapv -fPIC -fPIE -maes'
    #echo 'gcc -O2 -fomit-frame-pointer -fwrapv -fPIC -fPIE -maes'
    #echo 'clang -O2 -fomit-frame-pointer -fwrapv -fPIC -fPIE -maes'
    #echo 'gcc -O -fomit-frame-pointer -fwrapv -fPIC -fPIE -maes'
    #echo 'clang -O -fomit-frame-pointer -fwrapv -fPIC -fPIE -maes'
  fi
) > okcompilers/c
echo > okcompilers/cpp

./do-part init 1>/dev/null 2>/dev/null || :

(
  #echo "keccak"
  #echo "crypto_stream chacha8"
  #echo "crypto_stream aes256ctr"
  echo "crypto_stream chacha20"
  #echo "crypto_stream gimli24v1"
  #echo "crypto_stream salsa20"
  #echo "crypto_stream xsalsa20"
  #echo "crypto_hash gimli24v1"
  #echo "crypto_hash sha3512"
  #echo "crypto_hash sha512"
  #echo "crypto_hash shake256"
  #echo "crypto_onetimeauth poly1305"
  #echo "crypto_sort uint32"
  #echo "crypto_rng"
  #echo "crypto_kem mceliece8192128"
) | (
  while read x y; do
    ./do-part $x $y 1>/dev/null 2>/dev/null || :
    echo
    grep ' ok ' "bench/${shorthostname}/data" | cut -d ' ' -f 10,13,14 | sort -n
  done
)
cat "bench/${shorthostname}/data"
