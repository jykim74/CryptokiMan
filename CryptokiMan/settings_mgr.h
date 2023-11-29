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

    void setFindMaxObjectsCount( int nCounts );
    int getFindMaxObjectsCount();
    int findMaxObjectsCount() { return find_max_objects_count_; };
signals:

public slots:

private:
    void initialize();
    int file_read_size_;
    bool use_device_mech_;
    int find_max_objects_count_;

    Q_DISABLE_COPY(SettingsMgr)
};

#endif // SETTINGS_MGR_H
