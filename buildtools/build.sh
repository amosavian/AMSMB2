#!/bin/sh

for i in "$@" ; do
    if [[ $i == "--with-libkrb5" ]] ; then
        WITH_KRB5="YES"
        echo "Building with Kerberos 5."
        break
    fi
done

cd ..
rm -rf "libsmb2"
mkdir  "libsmb2"
mkdir  "libsmb2/include"
mkdir  "libsmb2/lib"
PACKAGE_DIRECTORY=`pwd`
export LIB_OUTPUT="${PACKAGE_DIRECTORY}/libsmb2/lib"
cd buildtools

brew update
for pkg in cmake automake autoconf libtool; do
    if brew list -1 | grep -q "^${pkg}\$"; then
        echo "Updating ${pkg}."
        brew upgrade $pkg &> /dev/null
    else
        echo "Installing ${pkg}."
        brew install $pkg > /dev/null
    fi
done

if [ ! -d libsmb2 ]; then
  git clone https://github.com/sahlberg/libsmb2
  cd libsmb2
  ./bootstrap
else
  cd libsmb2
fi

export OS=ios
export MINSDKVERSION=9.0
export USECLANG=1
export CFLAGS="-fembed-bitcode -DHAVE_SOCKADDR_LEN=1 -DHAVE_SOCKADDR_STORAGE=1"
export CPPFLAGS="-I${PACKAGE_DIRECTORY}/buildtools/include"
#export CPPFLAGS="-I/usr/local/opt/openssl/include"
export LDFLAGS="-L${LIB_OUTPUT}"
#export PKG_CONFIG_PATH="/usr/local/opt/openssl/lib/pkgconfig"

echo "Making libsmb2 static libararies"
if [[ -z "${WITH_KRB5}" ]]; then
    ../autoframework libsmb2.a --without-libkrb5 --disable-werror > /dev/null
else
    ../autoframework libsmb2.a --disable-werror  > /dev/null
fi

cd ..

echo  "Copying additional headers"
cp    "libsmb2/include/libsmb2-private.h" "${PACKAGE_DIRECTORY}/libsmb2/include/"
cp    "module.modulemap"                  "${PACKAGE_DIRECTORY}/libsmb2/include/"

rm -rf libsmb2
rm -rf include
rm -rf lib
