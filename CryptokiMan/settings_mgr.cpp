#include <QSettings>

#include "settings_mgr.h"

namespace  {
    const char *kBehaviorGroup = "CryptokiMan";
    const char *kSaveLibPath = "saveLibPath";
    const char *kSlotID = "slotId";
    const char *kP11LibPath = "p11LibPath";
    const char *kShowLogWindow = "showLogWindow";
}

SettingsMgr::SettingsMgr( QObject *parent) : QObject (parent)
{

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

void SettingsMgr::setShowLogWindow( bool bVal )
{
    QSettings settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kShowLogWindow, bVal );
    settings.endGroup();
}

bool SettingsMgr::showLogWindow()
{
    QSettings settings;

    bool val;

    settings.beginGroup(kBehaviorGroup);
    val = settings.value( kShowLogWindow, false).toBool();
    settings.endGroup();

    return val;
}
