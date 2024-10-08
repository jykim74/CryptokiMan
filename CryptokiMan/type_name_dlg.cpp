#include <QStringList>
#include "common.h"
#include "js_error.h"

#include "type_name_dlg.h"
#include "js_pkcs11.h"
#include "js_pki.h"

#include "man_applet.h"
#include "mainwindow.h"

static QStringList kTypeList = { "ErrorCode", "KeyType", "Object", "Attribute", "Mechanism" };

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
    initialize();
    mSearchBtn->setDefault(true);

    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

TypeNameDlg::~TypeNameDlg()
{

}

int TypeNameDlg::getType( const QString strInput )
{
    if( strInput.length() < 2 )
        return JTypeDecimail;

    QString strFirst = strInput.left(2).toUpper();

    if( strFirst == "CK" )
        return JTypeName;
    else if( strFirst == "0X" )
        return JTypeHex;
    else
        return JTypeDecimail;
}

void TypeNameDlg::initialize()
{
    mTypeCombo->addItems( kTypeList );
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
    int ret = -1;
    int nType = -1;
    long uValue = -1;
    QString strValue;
    QString strSearch = mSearchText->text().toUpper();
    QString strTarget = mTypeCombo->currentText();

    if( strSearch.length() < 1 )
    {
        manApplet->warningBox( tr( "Enter a search word"), this );
        mSearchText->setFocus();
        return;
    }

    nType = getType( strSearch );

    if( nType == JTypeDecimail )
    {
        if( isValidNumFormat( strSearch, 10 ) == false )
        {
            manApplet->warningBox( tr( "Invalid word" ), this );
            mSearchText->setFocus();
            return;
        }

        uValue = strSearch.toLong();
    }
    else if( nType == JTypeHex )
    {
        strValue = strSearch.mid( 2 );

        if( isValidNumFormat( strValue, 16 ) == false )
        {
            manApplet->warningBox( tr( "Invalid word" ), this );
            mSearchText->setFocus();
            return;
        }

        uValue = strValue.toLong( nullptr, 16 );
    }
    else
    {
        strValue = strSearch;
    }

    if( uValue >= 0 )
    {
        if( strTarget == "ErrorCode" )
            strValue = JS_PKCS11_GetCKRName( uValue );
        else if( strTarget == "KeyType" )
            strValue = JS_PKCS11_GetCKKName( uValue );
        else if( strTarget == "Object" )
            strValue = JS_PKCS11_GetCKOName( uValue );
        else if( strTarget == "Attribute" )
            strValue = JS_PKCS11_GetCKAName( uValue );
        else if( strTarget == "Mechanism" )
            strValue = JS_PKCS11_GetCKMName( uValue );

        if( strValue.length() < 3 )
        {
            manApplet->warningBox( tr( "There is no defined value." ), this );
            mSearchText->setFocus();
            return;
        }

        QString strFirst = strValue.left(2);
        if( strFirst != "CK" )
        {
            manApplet->warningBox( tr( "There is no defined value." ), this );
            mSearchText->setFocus();
            return;
        }
    }
    else
    {
        if( strValue.length() < 3 )
        {
            manApplet->warningBox( tr( "Invalid word" ), this );
            mSearchText->setFocus();
            return;
        }

        QString strFirst = strValue.left(3);

        if( strFirst == "CKR" )
        {
            uValue = JS_PKCS11_GetCKRType( strValue.toStdString().c_str() );
        }
        else if( strFirst == "CKK" )
        {
            uValue = JS_PKCS11_GetCKKType( strValue.toStdString().c_str() );
        }
        else if( strFirst == "CKO" )
        {
            uValue = JS_PKCS11_GetCKOType( strValue.toStdString().c_str() );
        }
        else if( strFirst == "CKA" )
        {
            uValue = JS_PKCS11_GetCKAType( strValue.toStdString().c_str() );
        }
        else if( strFirst == "CKM" )
        {
            uValue = JS_PKCS11_GetCKMType( strValue.toStdString().c_str() );
        }

        if( uValue < 0 )
        {
            manApplet->warningBox( tr( "There is no defined value." ), this );
            mSearchText->setFocus();
            return;
        }

        ret = 0;
    }

    mDecimalText->setText( QString("%1").arg( uValue ));
    QString strHex = QString( "%1" ).arg( uValue, sizeof(long) * 2, 16, QLatin1Char('0')).toUpper();
    mHexText->setText( QString( "0x%1UL" ).arg( strHex ));
    mNameText->setText( strValue );
}
