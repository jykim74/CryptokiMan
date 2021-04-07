#ifndef CLOSE_SESSION_DLG_H
#define CLOSE_SESSION_DLG_H

#include <QDialog>
#include "ui_close_session_dlg.h"

namespace Ui {
class CloseSessionDlg;
}

class CloseSessionDlg : public QDialog, public Ui::CloseSessionDlg
{
    Q_OBJECT

public:
    explicit CloseSessionDlg(QWidget *parent = nullptr);
    ~CloseSessionDlg();
    void setAll( bool all );
    void setSelectedSlot( int index );

private slots:
    virtual void accept();
    void slotChanged( int index );

private:
    void initialize();
    bool     all_;
};

#endif // CLOSE_SESSION_DLG_H
