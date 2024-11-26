#ifndef HSM_MAN_DLG_H
#define HSM_MAN_DLG_H

#include <QDialog>
#include "ui_hsm_man_dlg.h"

enum {
    HsmModeManage = 0,
    HsmModeSelectCert,
    HsmModeSelectPublicKey,
    HsmModeSelectPrivateKey,
    HsmModeSelectSecretKey
};

enum {
    TAB_CERT_IDX = 0,
    TAB_PUBLIC_IDX = 1,
    TAB_PRIVATE_IDX = 2,
    TAB_SECRET_IDX = 3
};

namespace Ui {
class HsmManDlg;
}

class HsmManDlg : public QDialog, public Ui::HsmManDlg
{
    Q_OBJECT

public:
    explicit HsmManDlg(QWidget *parent = nullptr);
    ~HsmManDlg();
    void setSelectedSlot( int index );
    void setMode( int nMode );
    void setTitle( const QString strTitle );

private slots:
    void slotChanged( int index );
    void showEvent(QShowEvent *event);
    void closeEvent(QCloseEvent *event );

    void changeTab(int index);
    void changeUsage();

    void loadCertList();
    void loadPublicList();
    void loadPrivateList();
    void loadSecretList();

    void clickCertView();
    void clickCertDelete();
    void clickCertExport();

    void clickPublicView();
    void clickPublicDelete();
    void clickPublicExport();

    void clickPrivateView();
    void clickPrivateDelete();
    void clickPrivateExport();

    void clickSecretView();
    void clickSecretDelete();

private:
    void initUI();
    void initialize();

    int slot_index_;
    long session_;
};

#endif // HSM_MAN_DLG_H
