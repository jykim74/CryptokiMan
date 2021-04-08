#ifndef SETTINGS_MGR_H
#define SETTINGS_MGR_H

#include <QObject>

class SettingsMgr : public QObject
{
    Q_OBJECT

public:
    SettingsMgr( QObject *parent = nullptr );

    void setSaveLibPath( bool val );
    bool saveLibPath();

    void setShowLogWindow( bool bVal );
    bool showLogWindow();
signals:

public slots:

private:
    Q_DISABLE_COPY(SettingsMgr)
};

#endif // SETTINGS_MGR_H
