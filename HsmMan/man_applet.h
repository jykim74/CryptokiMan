#ifndef MAN_APPLET_H
#define MAN_APPLET_H

#include <QObject>

class MainWindow;
class OpenSessionDlg;
class CloseSessionDlg;

class ManApplet : public QObject
{
    Q_OBJECT

public:
    ManApplet( QObject *parent = nullptr );
    void start();

    OpenSessionDlg* openSessionDlg() { return open_session_dlg_; };
    CloseSessionDlg* closeSessionDlg() { return close_session_dlg_; };

private:
    Q_DISABLE_COPY(ManApplet)

    MainWindow* main_win_;
    OpenSessionDlg* open_session_dlg_;
    CloseSessionDlg* close_session_dlg_;
};

extern ManApplet *manApplet;

#endif // MAN_APPLET_H
