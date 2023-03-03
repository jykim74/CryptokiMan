CULTURE = ko-kr
LANG_FILE = ko_KR.wxl
TARGET = CryptokiMan-ko.msi

ifeq (${MAKECMDGOALS}, en)
	CULTURE = en-us
	LANG_FILE = en_US.wxl
	TARGET = CryptokiMan-en.msi
endif
ifeq (${MAKECMDGOALS}, ko)
	CULTURE = ko-kr
	LANG_FILE = ko_KR.wxl
	TARGET = CryptokiMan-ko.msi
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

sources = WixUI_InstallDir_NoLicense.wxs MyInstallDirDlg.wxs fragment.wxs CryptokiMan.wxs

OBJECTS = ${sources:%.wxs=%.wixobj}

fragment.wxs:
	$(PARAFFIN) -dir ./CryptokiMan -gn group_bin -alias bin fragment.wxs
	cp -rf ./CryptokiMan/* ./bin

%.wixobj : %.wxs
	$(CC) $(CFLAGS) $< -o $@

CryptokiMan.wixobj : CryptokiMan.wxs Includes.wxi
	$(CC) $(CFLAGS) $< -o $@

$(TARGET) : $(OBJECTS) $(LANG_FILE)
	$(LD) $(LDFLAGS) $(OBJECTS) -o $@

clean :
	rm -f $(OBJECTS) *.msi fragment.*

rmbin :
	rm -f *.msi *.wixobj

.PHONY: all en ko clean
