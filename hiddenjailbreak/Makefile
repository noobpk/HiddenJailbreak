ARCHS := arm64 arm64e
TARGET := iphone:14.4:14.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = HiddenJailbreak

HiddenJailbreakCore= $(wildcard Core/*.m)

$(TWEAK_NAME)_FILES = $(HiddenJailbreakCore) Tweak.x
$(TWEAK_NAME)_EXTRA_FRAMEWORKS = Cephei
$(TWEAK_NAME)_PRIVATE_FRAMEWORKS = AppSupport
$(TWEAK_NAME)_CFLAGS = -fobjc-arc -DHiddenJailbreak="_$(shell git describe --always)"

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 SpringBoard"
SUBPROJECTS += HiddenJailbreakPreferences

include $(THEOS_MAKE_PATH)/aggregate.mk
