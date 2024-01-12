#ifndef EDIT_ATTRIBUTE_LIST_DLG_H
#define EDIT_ATTRIBUTE_LIST_DLG_H

#include <QDialog>
#include "ui_edit_attribute_list_dlg.h"

namespace Ui {
class EditAttributeListDlg;
}

class EditAttributeListDlg : public QDialog, public Ui::EditAttributeListDlg
{
    Q_OBJECT

public:
    explicit EditAttributeListDlg(QWidget *parent = nullptr);
    ~EditAttributeListDlg();

    void setSlotIndex( int index );
    void setObjectType( int type );
    void setObjectID( long id );

private slots:
    void showEvent(QShowEvent *event);
    void closeEvent(QCloseEvent *);

    void slotChanged( int index );
    void labelChanged( int index );
    void objectTypeChanged( int type );

    void changeLabel( const QString& text );
    void changeID( const QString& text );
    void changeApplication( const QString& text );
    void changeObjectID( const QString& text );

    void clickLabel();
    void clickID();
    void clickApplication();
    void clickObjectID();

    void clickClass();
    void clickKeyType();

    void clickPrivate();
    void clickSensitive();
    void clickWrap();
    void clickUnwrap();
    void clickEncrypt();
    void clickDecrypt();
    void clickModifiable();
    void clickCopyable();
    void clickDestroyable();
    void clickSign();
    void clickVerify();
    void clickToken();
    void clickTrusted();
    void clickExtractable();
    void clickDerive();
    void clickStartDate();
    void clickEndDate();

    void clickGetAttribute();
    void clickSetAttribute();

private:
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();

    void setDataAttributes();
    void setCertAttributes();
    void setSecretAttributes();
    void setPublicAttributes();
    void setPrivateAttributes();

    int slot_index_;
    int object_type_;
    long object_id_;
    long session_;
};

#endif // EDIT_ATTRIBUTE_LIST_DLG_H
