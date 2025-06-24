#ifndef OBJECT_VIEW_DLG_H
#define OBJECT_VIEW_DLG_H

#include <QDialog>
#include "ui_object_view_dlg.h"

namespace Ui {
class ObjectViewDlg;
}

class ObjectViewDlg : public QDialog, public Ui::ObjectViewDlg
{
    Q_OBJECT

public:
    explicit ObjectViewDlg(QWidget *parent = nullptr);
    ~ObjectViewDlg();
    void setObject( long hObject );

private:

};

#endif // OBJECT_VIEW_DLG_H
