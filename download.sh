#!/bin/sh

version="`cat version`"

if [ ! -f "supercop-${version}.tar.xz" ]; then
  curl "https://bench.cr.yp.to/supercop/supercop-${version}.tar.xz" > "supercop-${version}.tar.xz"
fi

if [ ! -d "supercop-${version}" ]; then
  tar vZxf "supercop-${version}.tar.xz"
fi

(
  cd "supercop-${version}"

  (
    rm -rf gmp-* ntl-* cryptopp-*
  )

  (
    cat OPERATIONS \
    | while read o; do
      [ -d "$o" ] || continue

      # for each operation, loop over primitives
      ls "$o" \
      | sort \
      | while read p; do
        ls "${o}/${p}" \
        | sort \
        | while read d; do
          [ -d "${o}/${p}/${d}" ] || continue
          echo ${o}/${p}/${d}
        done
      done
    done
  ) | (
    while read name; do
      rm -rf "${name}"
    done
  )

  # skip measurement, fix cp command
  sed -e 's,\"\$work/best/measure\",true,' -e 's/cp -Lpr/cp -LpR/' < do-part > do-part.tmp
  chmod 755 do-part
  mv -f do-part.tmp do-part
)

exit 0
