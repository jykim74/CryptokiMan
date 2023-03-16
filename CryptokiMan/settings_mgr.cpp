#include <QSettings>

#include "settings_mgr.h"

namespace  {
    const char *kBehaviorGroup = "CryptokiMan";
    const char *kSaveLibPath = "saveLibPath";
    const char *kSlotID = "slotId";
    const char *kP11LibPath = "p11LibPath";
    const char *kShowLogTab = "showLogTab";
    const char *kLogLevel = "logLevel";
}

SettingsMgr::SettingsMgr( QObject *parent) : QObject (parent)
{
    initialize();
}

void SettingsMgr::initialize()
{
    getLogLevel();
}

void SettingsMgr::setSaveLibPath( bool val )
{
    QSettings settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kSaveLibPath, val );
    settings.endGroup();
}

bool SettingsMgr::saveLibPath()
{
    QSettings settings;

    bool val;

    settings.beginGroup(kBehaviorGroup);
    val = settings.value( kSaveLibPath, false).toBool();
    settings.endGroup();

    return val;
}

void SettingsMgr::setShowLogTab( bool bVal )
{
    QSettings settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kShowLogTab, bVal );
    settings.endGroup();
}

bool SettingsMgr::showLogTab()
{
    QSettings settings;

    bool val;

    settings.beginGroup(kBehaviorGroup);
    val = settings.value( kShowLogTab, false).toBool();
    settings.endGroup();

    return val;
}

void SettingsMgr::setLogLevel( int nLevel )
{
    QSettings settings;
    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kLogLevel, nLevel );
    settings.endGroup();

    log_level_ = nLevel;
}

int SettingsMgr::getLogLevel()
{
    QSettings settings;

    settings.beginGroup( kBehaviorGroup );
    log_level_ = settings.value( kLogLevel, 2 ).toInt();
    settings.endGroup();

    return log_level_;
}
