#include <QSettings>

#include "settings_mgr.h"

namespace  {
    const char *kBehaviorGroup = "HsmMan";
    const char *kSaveLibPath = "saveLibPath";
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
