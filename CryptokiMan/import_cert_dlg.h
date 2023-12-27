#ifndef IMPORT_CERT_DLG_H
#define IMPORT_CERT_DLG_H

#include <QDialog>
#include "ui_import_cert_dlg.h"

namespace Ui {
class ImportCertDlg;
}

class ImportCertDlg : public QDialog, public Ui::ImportCertDlg
{
    Q_OBJECT

public:
    explicit ImportCertDlg(QWidget *parent = nullptr);
    ~ImportCertDlg();
    void setSelectedSlot( int index );

private slots:
    void slotChanged( int index );
    virtual void accept();
    void clickUseSKI();
    void clickUseSPKI();

    void clickPrivate();
    void clickModifiable();
    void clickCopyable();
    void clickDestroyable();
    void clickToken();
    void clickTrusted();
    void clickStartDate();
    void clickEndDate();

    void clickFind();
    void clickSubjectInCertCheck();

private:
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();
    void setDefaults();
};

#endif // IMPORT_CERT_DLG_H
