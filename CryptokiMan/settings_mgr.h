#ifndef SETTINGS_MGR_H
#define SETTINGS_MGR_H

#include <QObject>

class SettingsMgr : public QObject
{
    Q_OBJECT
private:
    int log_level_;

public:
    SettingsMgr( QObject *parent = nullptr );

    void setSaveLibPath( bool val );
    bool saveLibPath();

    void setShowLogTab( bool bVal );
    bool showLogTab();

    int logLevel() { return log_level_; };
    void setLogLevel( int nLevel );
    int getLogLevel();

    void setFileReadSize( int size );
    int getFileReadSize();
    int fileReadSize() { return file_read_size_; };
signals:

public slots:

private:
    void initialize();
    int file_read_size_;

    Q_DISABLE_COPY(SettingsMgr)
};

#endif // SETTINGS_MGR_H
