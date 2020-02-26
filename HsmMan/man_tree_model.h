#ifndef MAN_TREE_MODEL_H
#define MAN_TREE_MODEL_H

#include "js_pkcs11.h"

#include <QStandardItemModel>
#include <QTableWidget>

enum { ATTR_VAL_BOOL, ATTR_VAL_STRING, ATTR_VAL_HEX, ATTR_VAL_KEY_NAME, ATTR_VAL_LEN };

class ManTreeItem;

class ManTreeModel : public QStandardItemModel
{
public:
    ManTreeModel( QObject *parent = nullptr );


    void showGetInfo();
    void showSlotInfo( int index );
    void showTokenInfo( int index );
    void showMechanismInfo( int index );
    void showSessionInfo( int index );
    void showObjectsInfo( int index );
    void showCertificateInfo( int index, long hObject = -1 );
    void showPublicKeyInfo( int index, long hObject = -1 );
    void showPrivateKeyInfo( int index, long hObject = -1 );
    void showSecretKeyInfo( int index, long hObject = -1 );
    void showDataInfo( int index, long hObject = -1 );

    void setRightTable( QTableWidget *right_table );
    void removeAllRightTable();

private:
    void initialize();
    void showAttribute( int nSlotIdx, int nValType, CK_ATTRIBUTE_TYPE uAttribute, CK_OBJECT_HANDLE hObj );

    QTableWidget    *right_table_;

};

#endif // MAN_TREE_MODEL_H
