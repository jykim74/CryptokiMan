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
    int clickInit();
    void clickUpdate();
    void clickFinal();
    void clickDigest();
    void runDataDigest();
    void runFileDigest();
    void clickClose();

    void inputChanged();
    void outputChanged();

    void clickInputClear();
    void clickOutputClear();
    void clickFindSrcFile();

private:
    void initialize();
    void initUI();
    void setKeyList();

    long getSessionHandle();
};

#endif // DIGEST_DLG_H
