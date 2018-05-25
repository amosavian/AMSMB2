#!/bin/sh

for i in "$@" ; do
    if [[ $i == "--without-ssl" ]] ; then
        WITHOUT_SSL="YES"
        echo "Building without OpenSSL."
        break
    fi

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

if [[ -z "${WITHOUT_SSL}" ]]; then
: '    if brew ls --versions openssl > /dev/null; then
        echo "Updating openssl."
        brew upgrade openssl &> /dev/null
    else
        echo "Installing openssl."
        brew install openssl > /dev/null
    fi
'
    echo ""
    ./openssl-build.sh
fi

if [ ! -d libsmb2 ]; then
  git clone https://github.com/sahlberg/libsmb2
  cd libsmb2
  ./bootstrap
else
  cd libsmb2
fi


export MINSDKVERSION=9.0
export USECLANG=1
export CFLAGS="-fembed-bitcode -DHAVE_OPENSSL_LIBS=1 -DHAVE_SOCKADDR_LEN=1 -DHAVE_SOCKADDR_STORAGE=1"
export CPPFLAGS="-I${PACKAGE_DIRECTORY}/buildtools/include"
#export CPPFLAGS="-I/usr/local/opt/openssl/include"
export LDFLAGS="-L${LIB_OUTPUT}"
#export PKG_CONFIG_PATH="/usr/local/opt/openssl/lib/pkgconfig"

echo "Making libsmb2 static libararies"
if [[ -z "${WITH_KRB5}" ]]; then
    ../autoframework SMB2 libsmb2.a --without-libkrb5 --disable-werror > /dev/null
else
    ../autoframework SMB2 libsmb2.a --disable-werror > /dev/null
fi

cd ..

echo "Building libsmb2 library"
lipo \
	"libsmb2/Static/arm64/lib/libsmb2.a" \
    "libsmb2/Static/armv7/lib/libsmb2.a" \
    "libsmb2/Static/armv7s/lib/libsmb2.a" \
    "libsmb2/Static/i386/lib/libsmb2.a" \
    "libsmb2/Static/x86_64/lib/libsmb2.a" \
    -create -output "${LIB_OUTPUT}/libsmb2.a"

echo  "Copying headers"
cp    "libsmb2/include/libsmb2-private.h" "${PACKAGE_DIRECTORY}/libsmb2/include/"
cp -R "libsmb2/include/smb2"              "${PACKAGE_DIRECTORY}/libsmb2/include/"
cp    "module.modulemap"                  "${PACKAGE_DIRECTORY}/libsmb2/include/"

rm -rf libsmb2
rm -rf include
rm -rf lib
