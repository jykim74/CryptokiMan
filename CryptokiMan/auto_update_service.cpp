/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QSettings>
#include "auto_update_service.h"
#include "man_applet.h"
#include "i18n_helper.h"

#ifdef _AUTO_UPDATE

#ifdef Q_OS_WIN32
#include "winsparkle.h"
#else
#include "mac_sparkle_support.h"
#endif

SINGLETON_IMPL(AutoUpdateService)

namespace  {
#ifdef Q_OS_WIN32
    const char *kSparkleAppcastURI = "https://jykim74.github.io/appcast/cryptokiman_appcast_win.xml";
    const char *kSparkleAppcastURIForKR = "https://jykim74.github.io/appcast/cryptokiman_appcast_win_ko.xml";
    const char *kWinSparkleRegPath = "SOFTWARE\\JS Inc\\CryptokiMan\\WinSparkle";
#else
    const char *kSparkleAppcastURI = "https://jykim74.github.io/appcast/cryptokiman_appcast_mac.xml";
    const char *kSparkleAppcastURIForKR = "https://jykim74.github.io/appcast/cryptokiman_appcast_mac_ko.xml";
#endif
    const char *kSparkleAlreadyEnableUpdateByDefault = "SparkleAlreadyEnableUpdateByDefault";
}



QString getAppcastURI() {
    QString url_from_env = qgetenv("CRYPTOKI_MAN_APPCAST_URI");

    if( !url_from_env.isEmpty() )
    {
        qWarning( "winsparkle: using app cast url from CRYPTOKI_MAN_APPCAST_URI: "
                  "%s", url_from_env.toUtf8().data() );

        return url_from_env;
    }

//    return kSparkleAppcastURI;
    return I18NHelper::getInstance()->isKorea() ? kSparkleAppcastURIForKR : kSparkleAppcastURI;
}

class AutoUpdateAdapter {
public:
    virtual void prepare() = 0;
    virtual void start() = 0;
    virtual void stop() = 0;
    virtual void checkNow() = 0;
    virtual bool autoUpdateEnabled() = 0;
    virtual void setAutoUpdateEnabled(bool enabled) = 0;
};

#ifdef Q_OS_WIN32
class WindowsAutoUpdateAdapter: public AutoUpdateAdapter {
public:
    void prepare() {
        win_sparkle_set_registry_path(kWinSparkleRegPath);
        win_sparkle_set_appcast_url(getAppcastURI().toUtf8().data());
        win_sparkle_set_app_details(
                    L"JS Inc",
                    L"CryptokiMan",
                    QString(STRINGIZE(CRYPTOKIMAN_VERSION)).toStdWString().c_str() );
    }

    void start() {
        win_sparkle_init();
    }

    void stop() {
        win_sparkle_cleanup();
    }

    void checkNow() {
        win_sparkle_check_update_with_ui();
    }

    bool autoUpdateEnabled() {
        return win_sparkle_get_automatic_check_for_updates();
    }

    void setAutoUpdateEnabled(bool enabled) {
        win_sparkle_set_automatic_check_for_updates(enabled ? 1 : 0 );
    }
};
#elif defined(Q_OS_MAC)
class MacAutoUpdateAdapter: public AutoUpdateAdapter {
public:
    void prepare() {
        SparkleHelper::setFeedURL(getAppcastURI().toUtf8().data());
    }

    void start() {

    }

    void stop() {

    }

    void checkNow() {
        SparkleHelper::checkForUpdate();
    }

    bool autoUpdateEnabled() {
        return SparkleHelper::autoUpdateEnabled();
    }

    void setAutoUpdateEnabled(bool enabled)
    {
        SparkleHelper::setAutoUpdateEnabled(enabled);
    }
};
#endif

AutoUpdateService::AutoUpdateService(QObject *parent) : QObject(parent)
{
#ifdef Q_OS_WIN32
    adapter_ = new WindowsAutoUpdateAdapter;
#elif defined(Q_OS_MAC)
    adapter_ = new MacAutoUpdateAdapter;
#else

#endif
}

void AutoUpdateService::start()
{
    adapter_->prepare();
    enableUpdateByDefault();
    adapter_->start();
}

void AutoUpdateService::enableUpdateByDefault()
{
    QSettings settings;
    settings.beginGroup("Misc");
    bool already_enable_update_by_default = settings.value(kSparkleAlreadyEnableUpdateByDefault, false).toBool();

    if( !already_enable_update_by_default )
    {
        settings.setValue(kSparkleAlreadyEnableUpdateByDefault, true);
        setAutoUpdateEnabled(true);
    }

    settings.endGroup();
}

void AutoUpdateService::stop()
{
    adapter_->stop();
}

void AutoUpdateService::checkUpdate()
{
    adapter_->checkNow();
}

bool AutoUpdateService::shouldSupportAutoUpdate() const {
    return QString("CryptokiMan") == manApplet->getBrand();
}

bool AutoUpdateService::autoUpdateEnabled() const {
    return adapter_->autoUpdateEnabled();
}

void AutoUpdateService::setAutoUpdateEnabled(bool enabled) {
    adapter_->setAutoUpdateEnabled(enabled);
}

#endif
