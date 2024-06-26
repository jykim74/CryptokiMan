/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QSettings>

#include "settings_mgr.h"

namespace  {
    const char *kBehaviorGroup = "CryptokiMan";
    const char *kUseLogTab = "useLogTab";
    const char *kLogLevel = "logLevel";
    const char *kFileReadSize = "fileReadSize";
    const char *kUseDeviceMech = "useDeviceMech";
    const char *kFontFamily = "fontFamily";
    const char *kMisc = "Misc";
    const char *kEmail = "email";
    const char *kLicense = "license";
    const char *kStopMessage = "stopMessage";
    const char *kFindMaxObjectsCount = "findMaxObjectsCount";
    const char *kHexAreaWidth = "hexAreaWidth";
}

SettingsMgr::SettingsMgr( QObject *parent) : QObject (parent)
{
    file_read_size_ = 0;
    use_device_mech_ = false;

    initialize();
}

void SettingsMgr::removeSet( const QString& group, const QString& name )
{
    QSettings settings;

    settings.beginGroup(group);
    settings.remove( name );
    settings.endGroup();
}

void SettingsMgr::initialize()
{
    getLogLevel();
    getFileReadSize();
    getUseDeviceMech();
    getFindMaxObjectsCount();
    getHexAreaWidth();
}

void SettingsMgr::setUseLogTab( bool bVal )
{
    QSettings settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kUseLogTab, bVal );
    settings.endGroup();
}

bool SettingsMgr::getUseLogTab()
{
    QSettings settings;

    bool val;

    settings.beginGroup(kBehaviorGroup);
    val = settings.value( kUseLogTab, false).toBool();
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

#ifdef Q_OS_MAC
    QString strDefault = "Monaco";
#else
#ifdef Q_OS_LINUX
    QString strDefault = "Monospace";
#else
    QString strDefault = "Consolas";
#endif
#endif
    sets.beginGroup( kBehaviorGroup );
    QString strFamily = sets.value( kFontFamily, strDefault ).toString();
    sets.endGroup();

    return strFamily;
}

void SettingsMgr::setEmail( const QString strEmail )
{
    QSettings sets;
    sets.beginGroup( kMisc );
    sets.setValue( kEmail, strEmail );
    sets.endGroup();
}

QString SettingsMgr::getEmail()
{
    QSettings sets;

    sets.beginGroup( kMisc );
    QString strEmail = sets.value( kEmail, "" ).toString();
    sets.endGroup();

    return strEmail;
}

void SettingsMgr::setLicense( const QString strLicense )
{
    QSettings sets;
    sets.beginGroup( kMisc );
    sets.setValue( kLicense, strLicense );
    sets.endGroup();
}

QString SettingsMgr::getLicense()
{
    QSettings sets;

    sets.beginGroup( kMisc );
    QString strLicense = sets.value( kLicense, "" ).toString();
    sets.endGroup();

    return strLicense;
}

void SettingsMgr::setStopMessage( time_t tLastTime )
{
    QSettings sets;
    qint64 uLastTime = tLastTime;

    sets.beginGroup( kMisc );
    sets.setValue( kStopMessage, uLastTime );
    sets.endGroup();
}

time_t SettingsMgr::getStopMessage()
{
    QSettings sets;

    sets.beginGroup( kMisc );
    time_t tLastTime = sets.value( kStopMessage, -1 ).toInt();
    sets.endGroup();

    return tLastTime;
}


void SettingsMgr::setFindMaxObjectsCount( int nCounts )
{
    QSettings sets;
    sets.beginGroup( kBehaviorGroup );
    sets.setValue( kFindMaxObjectsCount, nCounts );
    sets.endGroup();

    find_max_objects_count_ = nCounts;
}

int SettingsMgr::getFindMaxObjectsCount()
{
    QSettings sets;

    sets.beginGroup( kBehaviorGroup );
    find_max_objects_count_ = sets.value( kFindMaxObjectsCount, 10 ).toInt();
    sets.endGroup();

    return find_max_objects_count_;
}

void SettingsMgr::setHexAreaWidth( int width )
{
    QSettings sets;
    sets.beginGroup( kBehaviorGroup );
    sets.setValue( kHexAreaWidth, width );
    sets.endGroup();

    hex_area_width_ = width;
}

int SettingsMgr::getHexAreaWidth()
{
    QSettings sets;

    sets.beginGroup( kBehaviorGroup );
    hex_area_width_ = sets.value( kHexAreaWidth, -1 ).toInt();
    sets.endGroup();

    return hex_area_width_;
}
