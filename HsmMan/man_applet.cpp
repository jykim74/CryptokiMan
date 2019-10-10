#include "man_applet.h"
#include "mainwindow.h"
#include "open_session_dlg.h"
#include "close_session_dlg.h"

ManApplet *manApplet;

ManApplet::ManApplet( QObject *parent )
{
    main_win_ = new MainWindow;
    open_session_dlg_ = new OpenSessionDlg;
    close_session_dlg_ = new CloseSessionDlg;
}

void ManApplet::start()
{
    main_win_->show();
}
