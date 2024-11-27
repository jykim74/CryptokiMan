#ifndef HSM_MAN_DLG_H
#define HSM_MAN_DLG_H

#include <QDialog>
#include "ui_hsm_man_dlg.h"
#include "js_pkcs11.h"

enum {
    HsmModeManage = 0,
    HsmModeSelectCert,
    HsmModeSelectPublicKey,
    HsmModeSelectPrivateKey,
    HsmModeSelectSecretKey
};

enum {
    HsmUsageAny = 0,
    HsmUsageSign,
    HsmUsageVerify,
    HsmUsageEncrypt,
    HsmUsageDecrypt,
    HsmUsageWrap,
    HsmUsageUnwrap
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
    void setMode( int nMode, int nUsage = HsmUsageAny );
    void setTitle( const QString strTitle );
    const QString getData() { return str_data_; };

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

    void clickOK();

private:
    void initUI();
    void initialize();
    void setUsageTemplate( CK_ATTRIBUTE sTemplate[], long& uCount );

    int slot_index_;
    long session_;
    QString str_data_;
};

#endif // HSM_MAN_DLG_H
