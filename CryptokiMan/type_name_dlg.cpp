#include "type_name_dlg.h"
#include "js_pkcs11.h"
#include "js_pki.h"

#include "man_applet.h"
#include "mainwindow.h"

TypeNameDlg::TypeNameDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);

    connect( mClearBtn, SIGNAL(clicked()), this, SLOT(clickClear()));
    connect( mSearchBtn, SIGNAL(clicked()), this, SLOT(clickSearch()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif

    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

TypeNameDlg::~TypeNameDlg()
{

}

void TypeNameDlg::clickClear()
{
    mSearchText->clear();
    mDecimalText->clear();
    mHexText->clear();
    mNameText->clear();
}

void TypeNameDlg::clickSearch()
{
    QString strSearch = mSearchText->text();

    if( strSearch.length() < 1 )
    {
        manApplet->warningBox( tr( "Enter a search word"), this );
        mSearchText->setFocus();
        return;
    }
}
