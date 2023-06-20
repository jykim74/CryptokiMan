#include <QSettings>

#include "settings_mgr.h"

namespace  {
    const char *kBehaviorGroup = "CryptokiMan";
    const char *kSaveLibPath = "saveLibPath";
    const char *kSlotID = "slotId";
    const char *kP11LibPath = "p11LibPath";
    const char *kShowLogTab = "showLogTab";
    const char *kLogLevel = "logLevel";
    const char *kFileReadSize = "fileReadSize";
}

SettingsMgr::SettingsMgr( QObject *parent) : QObject (parent)
{
    initialize();
}

void SettingsMgr::initialize()
{
    getLogLevel();
    getFileReadSize();
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

void SettingsMgr::setFileReadSize( int size )
{
    QSettings sets;
    sets.beginGroup( kBehaviorGroup );
    sets.setValue( kFileReadSize, size );
    sets.endGroup();

    file_read_size_ = size;
}

int SettingsMgr::getFileReadSize()
{
    QSettings sets;

    sets.beginGroup( kBehaviorGroup );
    file_read_size_ = sets.value( kFileReadSize, 10240 ).toInt();
    sets.endGroup();

    return file_read_size_;
}
