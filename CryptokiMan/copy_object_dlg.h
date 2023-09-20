#ifndef COPY_OBJECT_DLG_H
#define COPY_OBJECT_DLG_H

#include <QDialog>
#include "ui_copy_object_dlg.h"
#include "js_pkcs11.h"

namespace Ui {
class CopyObjectDlg;
}

class CopyObjectDlg : public QDialog, public Ui::CopyObjectDlg
{
    Q_OBJECT

public:
    explicit CopyObjectDlg(QWidget *parent = nullptr);
    ~CopyObjectDlg();

    void setSelectedSlot( int index );

private slots:
    virtual void accept();
    void slotChanged( int index );

    void changeType( int index );
    void changeLabel( int index );

private:
    void initUI();
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();
    void setDefaults();

    void readLabels( CK_OBJECT_CLASS objClass );

    void readSecretKeyLabels();
    void readPrivateKeyLabels();
    void readPublicKeyLabels();
    void readCertificateLabels();
    void readDataLabels();

    int slot_index_;
    long session_;
};

#endif // COPY_OBJECT_DLG_H
