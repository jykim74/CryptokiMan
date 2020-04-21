CULTURE = ko-kr
LANG_FILE = ko_KR.wxl
TARGET = HsmMan-ko.msi

ifeq (${MAKECMDGOALS}, en)
	CULTURE = en-us
	LANG_FILE = en_US.wxl
	TARGET = HsmMan-en.msi
endif
ifeq (${MAKECMDGOALS}, ko)
	CULTURE = ko-kr
	LANG_FILE = ko_KR.wxl
	TARGET = HsmMan-ko.msi
endif

all: $(TARGET)
en: all
ko: all

CC=/c/bin/wix/candle.exe
LD=/c/bin/wix/light.exe
PARAFFIN=/c/bin/Paraffin.exe

CFLAGS = -ext WixUIExtension -ext WixUtilExtension
LDFLAGS = -spdb -ext WixUIExtension -ext WixUtilExtension \
		-loc ${LANG_FILE} -cultures:${CULTURE} -sice:ICE80

sources = WixUI_InstallDir_NoLicense.wxs MyInstallDirDlg.wxs fragment.wxs HsmMan.wxs

OBJECTS = ${sources:%.wxs=%.wixobj}

fragment.wxs:
	$(PARAFFIN) -dir ./HsmMan -gn group_bin -alias bin fragment.wxs
	cp -rf ./HsmMan/* ./bin

%.wixobj : %.wxs
	$(CC) $(CFLAGS) $< -o $@

HsmMan.wixobj : HsmMan.wxs Includes.wxi
	$(CC) $(CFLAGS) $< -o $@

$(TARGET) : $(OBJECTS) $(LANG_FILE)
	$(LD) $(LDFLAGS) $(OBJECTS) -o $@

clean :
	rm -f $(OBJECTS) *.msi fragment.*

rmbin :
	rm -f *.msi *.wixobj

.PHONY: all en ko clean
