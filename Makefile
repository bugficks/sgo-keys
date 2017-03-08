################################################################################
#
# bugficks@samygo
# (c) 2016 - inf
#
# License: GPLv2
#
################################################################################

CROSS_COMPILE?=/opt/vd/armv7l-tizen/bin/armv7l-tizen-linux-gnueabi-
KDIR?=/opt/vd/kernel/hawk/linux-3.10.28.Open

export SDP?=
export KMOD_VER?=0134

################################################################################
#
ifeq (${MAKELEVEL},0)
$(info -------------------------------------------------------------------------)

$(shell touch ${KDIR}/.config)
include ${KDIR}/.config

ifeq (${CONFIG_ARCH_SDP1404},y)
    $(info $${KDIR}/.config CONFIG_ARCH_SDP1404: ${CONFIG_ARCH_SDP1404})
    SDP:=1404
else ifeq (${CONFIG_ARCH_SDP1406},y)
    $(info $${KDIR}/.config CONFIG_ARCH_SDP1406: ${CONFIG_ARCH_SDP1406})
    SDP:=1406
else
    ifeq (${SDP}, 1406)
        export KCONFIG_CONFIG=${KDIR}/arch/arm/configs/Hawk.M-Tizen_release_defconfig
    else ifeq (${SDP}, 1404)
        export KCONFIG_CONFIG=${KDIR}/arch/arm/configs/Hawk.P-Tizen_release_defconfig
    else
        ifneq (${MAKECMDGOALS}, clean)
            $(error Invalid $${SDP} value: ${SDP})
        endif
    endif

    $(info No or invalid $${KDIR}/.config)
    $(info Using SDP: ${SDP})
    $(info KCONFIG_CONFIG: $(patsubst ${KDIR}/%,$${KDIR}/%,${KCONFIG_CONFIG}))
endif

$(info -------------------------------------------------------------------------)
endif # ifeq(${MAKELEVEL},0)
################################################################################

ifeq (${SDP}, 1404)
	SDP_ARCH=Hawk.P-Tizen
endif

ifeq (${SDP}, 1406)
	SDP_ARCH=Hawk.M-Tizen
endif

################################################################################

ccflags-y += -I${KDIR}
ccflags-y += -Wno-unused-function
ccflags-y += -Wno-implicit-int
ccflags-y += -Wno-declaration-after-statement
ccflags-y += -Wno-unused-variable

ccflags-y += -DCONFIG_KEYS

################################################################################

KMOD_NAME=sgo-keys_sdp${SDP}

obj-m := ${KMOD_NAME}.o
${KMOD_NAME}-y += sgo_keys.o
${KMOD_NAME}-y += utils.o
${KMOD_NAME}-y += llist.o

################################################################################

all: vdlp_version
	make -C $(KDIR)/${O} O=${O} M=${CURDIR} clean
	make -C $(KDIR)/${O} O=${O} modules_prepare ARCH=arm CROSS_COMPILE="$(CROSS_COMPILE)"
	make -C $(KDIR)/${O} O=${O} M=${CURDIR} modules ARCH=arm CROSS_COMPILE="$(CROSS_COMPILE)"
	${CROSS_COMPILE}strip --strip-unneeded --discard-locals ${KMOD_NAME}.ko

clean:
	make -C $(KDIR)/${O} O=${O} M=${CURDIR} clean ARCH=arm CROSS_COMPILE="$(CROSS_COMPILE)"
	@-rm -rf ${CURDIR}/release/

install:
	make -C $(KDIR)/${O} O=${O} M=${CURDIR} modules_install ARCH=arm CROSS_COMPILE="$(CROSS_COMPILE)" \
             INSTALL_MOD_STRIP=1 INSTALL_MOD_PATH=${CURDIR}/release/

vdlp_version: VDLP_H=${KDIR}/include/linux/vdlp_version.h
vdlp_version:
	@echo Creating $(subst ${KDIR}/,,${VDLP_H})
	@echo '#define DTV_KERNEL_VERSION "${KMOD_VER}, release"' > ${VDLP_H}
	@echo '#define DTV_LAST_PATCH "SamyGO, DTV, ${SDP_ARCH}, release, HawkAll_DVB_RCA"' >> ${VDLP_H}
