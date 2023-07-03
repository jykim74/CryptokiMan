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
    const char *kUseDeviceMech = "useDeviceMech";
    const char *kFontFamily = "fontFamily";
}

SettingsMgr::SettingsMgr( QObject *parent) : QObject (parent)
{
    file_read_size_ = 0;
    use_device_mech_ = false;

    initialize();
}

void SettingsMgr::initialize()
{
    getLogLevel();
    getFileReadSize();
    getUseDeviceMech();
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
    file_read_size_ = sets.value( kFileReadSize, 1024 ).toInt();
    sets.endGroup();

    return file_read_size_;
}

void SettingsMgr::setUseDeviceMech( bool bVal )
{
    QSettings sets;
    sets.beginGroup( kBehaviorGroup );
    sets.setValue( kUseDeviceMech, bVal );
    sets.endGroup();

    use_device_mech_ = bVal;
}

bool SettingsMgr::getUseDeviceMech()
{
    QSettings sets;

    sets.beginGroup( kBehaviorGroup );
    use_device_mech_ = sets.value( kUseDeviceMech, false ).toBool();
    sets.endGroup();

    return use_device_mech_;
}

void SettingsMgr::setFontFamily( const QString& strFamily )
{
    QSettings sets;
    sets.beginGroup( kBehaviorGroup );
    sets.setValue( kFontFamily, strFamily );
    sets.endGroup();
}

QString SettingsMgr::getFontFamily()
{
    QSettings sets;

    sets.beginGroup( kBehaviorGroup );
    QString strFamily = sets.value( kFontFamily, "굴림체" ).toString();
    sets.endGroup();

    return strFamily;
}
