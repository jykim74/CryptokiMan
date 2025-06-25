#ifndef OBJECT_VIEW_DLG_H
#define OBJECT_VIEW_DLG_H

#include <QDialog>
#include "slot_info.h"
#include "ui_object_view_dlg.h"

#include "js_pkcs11.h"

namespace Ui {
class ObjectViewDlg;
}

class ObjectViewDlg : public QDialog, public Ui::ObjectViewDlg
{
    Q_OBJECT

public:
    explicit ObjectViewDlg(QWidget *parent = nullptr);
    ~ObjectViewDlg();

    void setSlotIndex( int index );
    int getSlotIndex() { return slot_index_; };

    void setObject( long hObject );

private slots:
    void clickReload();

    void clickCommonField( QModelIndex index );
    void clickPart1Field( QModelIndex index );
    void clickPart2Field( QModelIndex index );
    void clickPart3Field( QModelIndex index );

private:
    void initialize();
    void initUI();
    QString stringAttribute( int nValType, CK_ATTRIBUTE_TYPE uAttribute, CK_OBJECT_HANDLE hObj, int *pnRet );

    void setCertificate( long hObject );
    void setPublicKey( long hObject );
    void setPrivateKey( long hObject );
    void setSecretKey( long hObject );
    void setData( long hObject );

    SlotInfo slot_info_;
    int slot_index_ = -1;
};

#endif // OBJECT_VIEW_DLG_H
