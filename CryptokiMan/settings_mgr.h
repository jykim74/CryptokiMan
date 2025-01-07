/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef SETTINGS_MGR_H
#define SETTINGS_MGR_H

#include <QObject>
#include "common.h"

namespace  {
const char *kBehaviorGroup = "CryptokiMan";
const char *kUseLogTab = "useLogTab";
const char *kSetLogLevel = "SetLogLevel";
const char *kFileReadSize = "fileReadSize";
const char *kUseDeviceMech = "useDeviceMech";
const char *kFontFamily = "fontFamily";
const char *kMisc = "Misc";
const char *kEmail = "email";
const char *kLicense = "license";
const char *kStopMessage = "stopMessage";
const char *kFindMaxObjectsCount = "findMaxObjectsCount";
const char *kHexAreaWidth = "hexAreaWidth";
const char *kViewFile = "viewFile";
const char *kViewModule = "viewModule";
const char *kViewObject = "viewObject";
const char *kViewCrypt = "viewCrypt";
const char *kViewImport = "viewImport";
const char *kViewTool = "viewTool";
const char *kViewHelp = "viewHelp";
const char *kRunTime = "runTime";
}

class SettingsMgr : public QObject
{
    Q_OBJECT

private:
    int log_level_;

public:
    SettingsMgr( QObject *parent = nullptr );
    void removeSet( const QString& group, const QString& name );

    void setUseLogTab( bool bVal );
    bool getUseLogTab();

    int logLevel() { return log_level_; };
    void setLogLevel( int nLevel );
    int getLogLevel();

    void setFileReadSize( int size );
    int getFileReadSize();
    int fileReadSize() { return file_read_size_; };

    void setUseDeviceMech( bool bVal );
    bool getUseDeviceMech();
    bool useDeviceMech() { return use_device_mech_; };

    void setFontFamily( const QString& strFamily );
    QString getFontFamily();

    void setEmail( const QString strEmail );
    QString getEmail();

    void setLicense( const QString strLicense );
    QString getLicense();

    void setStopMessage( time_t tLastTime );
    time_t getStopMessage();

    void setFindMaxObjectsCount( int nCounts );
    int getFindMaxObjectsCount();
    int findMaxObjectsCount() { return find_max_objects_count_; };

    void setHexAreaWidth( int width );
    int getHexAreaWidth();
    int hexAreaWidth() { return hex_area_width_; };

    int viewValue( int nType );
    int getViewValue( int nType );
    void setViewValue( int nVal );
    void clearViewValue( int nType );

    void setRunTime( time_t tRun );
    time_t getRunTime();

private:
    void initialize();

private:
    int file_read_size_;
    bool use_device_mech_;
    int find_max_objects_count_;
    int hex_area_width_;

    int view_file_;
    int view_module_;
    int view_object_;
    int view_crypt_;
    int view_import_;
    int view_tool_;
    int view_help_;

private:
    Q_DISABLE_COPY(SettingsMgr)
};

#endif // SETTINGS_MGR_H
