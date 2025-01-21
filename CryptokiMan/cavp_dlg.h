#ifndef CAVP_DLG_H
#define CAVP_DLG_H

#include <QDialog>
#include "ui_cavp_dlg.h"

namespace Ui {
class CAVPDlg;
}

class CAVPDlg : public QDialog, public Ui::CAVPDlg
{
    Q_OBJECT

public:
    explicit CAVPDlg(QWidget *parent = nullptr);
    ~CAVPDlg();

    void setSelectedSlot( int index );

private slots:
    void slotChanged( int index );

private:
    void initialize();

    long session_;
    int slot_index_;
};

#endif // CAVP_DLG_H
