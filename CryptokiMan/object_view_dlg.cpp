#include "object_view_dlg.h"

ObjectViewDlg::ObjectViewDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
}

ObjectViewDlg::~ObjectViewDlg()
{

}

void ObjectViewDlg::setObject( long hObject )
{

}
