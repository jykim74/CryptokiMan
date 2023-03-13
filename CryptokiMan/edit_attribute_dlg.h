#ifndef EDIT_ATTRIBUTE_DLG_H
#define EDIT_ATTRIBUTE_DLG_H

#include <QDialog>
#include "ui_edit_attribute_dlg.h"

namespace Ui {
class EditAttributeDlg;
}

class EditAttributeDlg : public QDialog, public Ui::EditAttributeDlg
{
    Q_OBJECT

public:
    explicit EditAttributeDlg(QWidget *parent = nullptr);
    ~EditAttributeDlg();

    void setSlotIndex( int index );
    void setObjectIndex( int index );
    void setObjectID( long id );
    void setAttrName( const QString& strName );

private slots:
    virtual void accept();
    void showEvent(QShowEvent *event);
    void closeEvent(QCloseEvent *);

    void slotChanged( int index );
    void labelChanged( int index );
    void objectChanged( int index );

    void clickClose();
    void clickGetAttribute();
    void clickSetAttribute();

private:
    void initialize();
    void initAttributes();

    int slot_index_;
    int object_index_;
    long object_id_;
    QString attr_name_;
};

#endif // EDIT_ATTRIBUTE_DLG_H
