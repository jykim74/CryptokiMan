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
    void setSelectedSlot( int index );

private slots:
    void slotChanged( int index );
    void changeKeyLabel( int index );

    void clickDigestKey();
    void clickInit();
    void clickUpdate();
    void clickFinal();
    void clickDigest();
    void clickClose();

    void inputChanged();
    void outputChanged();

private:
    void initialize();
    void initUI();
    void setKeyList();

    long getSessinHandle();
};

#endif // DIGEST_DLG_H
