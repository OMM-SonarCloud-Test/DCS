#!/bin/bash

# uncomment for debug
#set -x

echo "Compile and build DCS"

source $(dirname "$0")/setenv.sh

SKIP_TESTS="-Dmaven.test.skip=true"
MVN="mvn -q ${SKIP_TESTS}"

echo "----------------------------------------"
echo "Java Version used in this build"
echo "----------------------------------------"
if [ -n "${JAVA_HOME}" ]; then
  "${JAVA_HOME}"/bin/java -version
else
  java -version
fi
echo "----------------------------------------"

echo "----------------------------------------"
echo "AMMOS CryptoLib"
echo "----------------------------------------"
if [ -x /usr/bin/cmake ]; then
cd $SRC_CRYPTO_LIB
if [ -f CMakeCache.txt ]; then
  make clean
  rm -f CMakeCache.txt make.out
fi
#cmake -DMYSQL=ON -DDEBUG=OFF -DLIBGCRYPT=ON -DKMCCRYPTO=ON -DTEST_ENC=OFF . > make.out
cmake -DDEBUG=OFF -DCRYPTO_KMC=ON -DCRYPTO_LIBGCRYPT=ON -DKEY_KMC=ON -DMC_DISABLED=ON -DSA_MARIADB=ON -DSA_INTERNAL=ON -DTEST=OFF -DSA_FILE=OFF -DKMC_MDB_DB=ON -DCODECOV=OFF . > make.out
if [ $? != 0 ]; then
  echo "ERROR: Failed cmake in $SRC_CRYPTO_LIB"
  exit 1
fi
make >> make.out
if [ $? != 0 ]; then
  echo "ERROR: Failed to build $SRC_CRYPTO_LIB"
  exit 1
fi
make install >> make.out
else
  echo "Skip building CryptoLib as cmake not found"
fi
echo "----------------------------------------"

cd $SRC_KMC; mvn -q clean
cd $SRC_KMC; $MVN install -N -DDEFAULT_PREFIX="${PREFIX}" -DDEFAULT_BINPATH="${BINPATH}" -DDEFAULT_LIBPATH="${LIBPATH}" -DDEFAULT_CFGPATH="${CFGPATH}" -DDEFAULT_LOGPATH="${LOGPATH}"


echo "----------------------------------------"
echo "KMIP Client Library"
echo "----------------------------------------"
cd $SRC_KMIP; mvn -q clean
cd $SRC_KMIP; $MVN install -DDEFAULT_PREFIX="${PREFIX}" -DDEFAULT_BINPATH="${BINPATH}" -DDEFAULT_LIBPATH="${LIBPATH}" -DDEFAULT_CFGPATH="${CFGPATH}" -DDEFAULT_LOGPATH="${LOGPATH}"
echo "----------------------------------------"
echo "DCS Key Client Library"
echo "----------------------------------------"
cd $SRC_KMC/kmc-key-client ; $MVN install -DDEFAULT_PREFIX="${PREFIX}" -DDEFAULT_BINPATH="${BINPATH}" -DDEFAULT_LIBPATH="${LIBPATH}" -DDEFAULT_CFGPATH="${CFGPATH}" -DDEFAULT_LOGPATH="${LOGPATH}"
echo "----------------------------------------"
echo "DCS Crypto Interface"
echo "----------------------------------------"
cd $SRC_KMC/kmc-crypto ; $MVN install -DDEFAULT_PREFIX="${PREFIX}" -DDEFAULT_BINPATH="${BINPATH}" -DDEFAULT_LIBPATH="${LIBPATH}" -DDEFAULT_CFGPATH="${CFGPATH}" -DDEFAULT_LOGPATH="${LOGPATH}"
echo "----------------------------------------"
echo "DCS Crypto Library"
echo "----------------------------------------"
cd $SRC_KMC/kmc-crypto-library ; $MVN install -DDEFAULT_PREFIX="${PREFIX}" -DDEFAULT_BINPATH="${BINPATH}" -DDEFAULT_LIBPATH="${LIBPATH}" -DDEFAULT_CFGPATH="${CFGPATH}" -DDEFAULT_LOGPATH="${LOGPATH}"
echo "----------------------------------------"
echo "DCS Crypto Service"
echo "----------------------------------------"
cd $SRC_KMC/kmc-crypto-service ; $MVN package -DDEFAULT_PREFIX="${CRYPTOSVC_PREFIX}" -DDEFAULT_BINPATH="${CRYPTOSVC_PREFIX}/bin" -DDEFAULT_LIBPATH="${CRYTPOSVC_LIBPATH}" -DDEFAULT_CFGPATH="${CRYPTOSVC_CFGPATH}" -DDEFAULT_LOGPATH="${CRYPTOSVC_LOGPATH}"

echo "----------------------------------------"
echo "DCS SDLS Service"
echo "----------------------------------------"
cd $SRC_KMC/kmc-sdls-service
export LD_LIBRARY_PATH=${SRC_CRYPTO_LIB}/build/lib
rm -fr local-maven-repo
rm -fr ~/.m2/repository/gov/nasa/jpl/ammos/asec/kmc/KmcSdlsJNI
mvn deploy:deploy-file -DgroupId=gov.nasa.jpl.ammos.asec.kmc -DartifactId=KmcSdlsJNI \
  -Dversion=$VERSION -Durl=file:./local-maven-repo/ -DrepositoryId=local-maven-repo \
  -DupdateReleaseInfo=true -Dfile=${SRC_CRYPTO_LIB}/build/lib/KmcSdlsJNI.jar
mvn eclipse:eclipse
mvn -q package -DDEFAULT_PREFIX="${SDLSSVC_PREFIX}" -DDEFAULT_BINPATH="${SDLSSVC_PREFIX}/bin" -DDEFAULT_LIBPATH="${SDLSSVC_LIBPATH}" -DDEFAULT_CFGPATH="${SDLSSVC_CFGPATH}" -DDEFAULT_LOGPATH="${SDLSSVC_LOGPATH}"

echo "----------------------------------------"
echo "DCS SA Management"
echo "----------------------------------------"
cd $SRC_KMC/kmc-sa-mgmt ; mvn -q package -DDEFAULT_PREFIX="${SAMGMTSVC_PREFIX}" -DDEFAULT_BINPATH="${SAMGMTSVC_PREFIX}/bin" -DDEFAULT_LIBPATH="${SAMGMTSVC_LIBPATH}" -DDEFAULT_CFGPATH="${SAMGMTSVC_CFGPATH}" -DDEFAULT_LOGPATH="${SAMGMTSVC_LOGPATH}" # will run the tests

if [ "$1" == "skip-test" ]; then
  cd $SRC_KMC/kmc-crypto-library ; mvn jar:test-jar
else
  echo "----------------------------------------"
  echo "DCS Crypto Library Tests"
  echo "----------------------------------------"
  cd $SRC_KMC/kmc-crypto-library ; mvn test ; mvn jar:test-jar
fi
