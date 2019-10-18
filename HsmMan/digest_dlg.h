#ifndef DIGEST_DLG_H
#define DIGEST_DLG_H

#include <QDialog>
#include "ui_digest_dlg.h"

namespace Ui {
class DigestDlg;
}

class DigestDlg : public QDialog, public Ui::DigestDlg
{
    Q_OBJECT

public:
    explicit DigestDlg(QWidget *parent = nullptr);
    ~DigestDlg();

private slots:
    void showEvent(QShowEvent *event);
    void slotChanged( int index );

    void clickInit();
    void clickUpdate();
    void clickFinal();
    void clickDigest();
    void clickClose();

private:
    void initialize();
    void initUI();
};

#endif // DIGEST_DLG_H
