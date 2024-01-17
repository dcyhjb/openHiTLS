#!/bin/bash

# ---------------------------------------------------------------------------------------------
#  This file is part of the openHiTLS project.
#  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
#  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
#  for license information.
# ---------------------------------------------------------------------------------------------

set -e
cd ../../
HITLS_ROOT_DIR=`pwd`

hilts_compile_option=()

paramList=$@
paramNum=$#
add_options=""
del_options=""
get_arch=`arch`

LIB_TYPE="static"
NO_SCTP="OFF"
BITS=64

clean()
{
    rm -rf ${HITLS_ROOT_DIR}/build
    mkdir ${HITLS_ROOT_DIR}/build
}

down_depend_code()
{
    if [ ! -d "${HITLS_ROOT_DIR}/platform" ]; then
        cd ${HITLS_ROOT_DIR}
        mkdir platform
    fi

    if [ ! -d "${HITLS_ROOT_DIR}/platform/Secure_C" ]; then
        cd ${HITLS_ROOT_DIR}/platform
        git clone https://gitee.com/openeuler/libboundscheck.git  Secure_C
    fi
}

build_depend_code()
{
    if [ ! -d "${HITLS_ROOT_DIR}/platform/Secure_C/lib" ]; then
        mkdir -p ${HITLS_ROOT_DIR}/platform/Secure_C/lib
        cd ${HITLS_ROOT_DIR}/platform/Secure_C
        make -j
    fi
}

build_hilts_code()
{
    bsl_features="err hash init list log sal sal_mem sal_thread sal_lock sal_time sal_file sal_net sal_str tlv \
                  uio_plt uio_buffer uio_sctp uio_tcp usrdata"
    if [[ "$NO_SCTP" = "ON" ]]; then
        bsl_features="${bsl_features//uio_sctp/}"
    fi

    # Compile openHiTLS
    cd ${HITLS_ROOT_DIR}/build
    python3 ../configure.py --enable ${bsl_features} hitls_crypto hitls_tls --bits=$BITS --system=linux
    if [[ $get_arch = "x86_64" ]]; then
        echo "Compile: env=x86_64, c, little endian, 64bits"
        python3 ../configure.py --lib_type ${LIB_TYPE} --add_options="$add_options" --del_options="$del_options"
    elif [[ $get_arch = "armv8_be" ]]; then
        echo "Compile: env=armv8, asm + c, big endian, 64bits"
        python3 ../configure.py --lib_type ${LIB_TYPE} --endian big --asm_type armv8 --add_options="$add_options" --del_options="$del_options"
    elif [[ $get_arch = "armv8_le" ]]; then
        echo "Compile: env=armv8, asm + c, little endian, 64bits"
        python3 ../configure.py --lib_type ${LIB_TYPE} --asm_type armv8 --add_options="$add_options" --del_options="$del_options"
    else
        echo "Compile: env=$get_arch, c, little endian, 64bits"
        python3 ../configure.py --lib_type ${LIB_TYPE} --add_options="$add_options" --del_options="$del_options"
    fi
    cmake ..
    make -j
}

parse_option()
{
    for i in $paramList
    do
        key=${i%%=*}
        value=${i#*=}
        case "${key}" in
            "gcov")
                add_options="${add_options} -fno-omit-frame-pointer -fprofile-arcs -ftest-coverage -fdump-rtl-expand"
                ;;
            "debug")
                add_options="${add_options} -O0 -g3 -gdwarf-2"
                del_options="${del_options} -O2 -D_FORTIFY_SOURCE=2"
                ;;
            "asan")
                add_options="${add_options} -fsanitize=address -fsanitize-address-use-after-scope -O0 -g3 -fno-stack-protector -fno-omit-frame-pointer -fgnu89-inline"
                del_options="${del_options} -fstack-protector-strong -fomit-frame-pointer -O2 -D_FORTIFY_SOURCE=2"
                ;;
            "armv8_be")
                get_arch="armv8_be"
                ;;
            "armv8_le")
                get_arch="armv8_le"
                ;;
            "no_sctp")
                NO_SCTP="ON"
                ;;
            "bits")
                BITS="$value"
                ;;
            "shared")
                LIB_TYPE="shared"
                ;;
            "help")
                printf "%-50s %-30s\n" "Build openHiTLS Code"                      "sh build_hitls.sh"
                printf "%-50s %-30s\n" "Build openHiTLS Code With Gcov"            "sh build_hitls.sh gcov"
                printf "%-50s %-30s\n" "Build openHiTLS Code With Debug"           "sh build_hitls.sh debug"
                printf "%-50s %-30s\n" "Build openHiTLS Code With Asan"            "sh build_hitls.sh asan"
                exit 0
                ;;
            *)
                echo "${i} option is not recognized, Please run <sh build_hitls.sh> get supported options."
                exit -1
                ;;
        esac
    done
}

clean
parse_option
down_depend_code
build_depend_code
build_hilts_code
